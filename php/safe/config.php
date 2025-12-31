<?php
/*
==============================================================================
 CONFIG.PHP — SAFE VERSION WITH STRONG XSS MITIGATION
==============================================================================
This file contains:
- session hardening
- CSRF protection
- output escaping
- CSP (Content Security Policy)
- database initialization

Application logic is NOT changed.
Only security layers are added.
==============================================================================
*/

/*
|--------------------------------------------------------------------------
| ERROR HANDLING — PREVENT INFORMATION DISCLOSURE
|--------------------------------------------------------------------------
*/
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');
error_reporting(E_ALL);

/*
|--------------------------------------------------------------------------
| SESSION HARDENING
|--------------------------------------------------------------------------
*/
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
        'cookie_secure'  => false, // true on HTTPS
        'use_strict_mode'=> true,
    ]);
}

/*
|--------------------------------------------------------------------------
| CONTENT SECURITY POLICY — XSS KILL SWITCH
|--------------------------------------------------------------------------
| Even if XSS appears, JavaScript will NOT execute.
| This blocks:
| - <script>
| - inline JS
| - event handlers (onerror, onload, etc.)
*/
header(
    "Content-Security-Policy: ".
    "default-src 'self'; ".
    "script-src 'self'; ".
    "style-src 'self' 'unsafe-inline'; ".
    "img-src 'self' data:; ".
    "object-src 'none'; ".
    "base-uri 'none'; ".
    "frame-ancestors 'none';"
);

/*
|--------------------------------------------------------------------------
| CSRF TOKEN
|--------------------------------------------------------------------------
*/
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function generate_csrf_token(){
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($t){
    return is_string($t) && hash_equals($_SESSION['csrf_token'], $t);
}

/*
|--------------------------------------------------------------------------
| OUTPUT ESCAPING — CORE XSS PROTECTION
|--------------------------------------------------------------------------
| This converts:
| <script>alert(1)</script>
| INTO:
| &lt;script&gt;alert(1)&lt;/script&gt;
|
| IMPORTANT:
| - Escape ONLY on OUTPUT
| - Never escape before saving to DB
*/
function e($s){
    return htmlspecialchars(
        (string)$s,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

/*
|--------------------------------------------------------------------------
| DATABASE INITIALIZATION
|--------------------------------------------------------------------------
*/
try {
    $pdo = new PDO('sqlite:' . __DIR__ . '/database.sqlite');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    $pdo->exec("PRAGMA foreign_keys = ON;");
} catch (Exception $e) {
    error_log("[DB ERROR] ".$e->getMessage());
    exit('Database error');
}

/*
|--------------------------------------------------------------------------
| SECURITY LOGGING
|--------------------------------------------------------------------------
*/
function security_log($level, $msg, $meta=[]){
    $logdir = __DIR__.'/logs';
    if (!is_dir($logdir)) @mkdir($logdir,0750,true);

    $entry = json_encode([
        'ts'   => date('c'),
        'lvl'  => $level,
        'msg'  => $msg,
        'meta' => $meta,
        'ip'   => $_SERVER['REMOTE_ADDR'] ?? 'cli'
    ], JSON_UNESCAPED_SLASHES);

    @file_put_contents(
        $logdir.'/security.log',
        $entry.PHP_EOL,
        FILE_APPEND | LOCK_EX
    );
}
