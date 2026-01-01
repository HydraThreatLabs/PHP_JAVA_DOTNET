<?php
// ==========================
// config.php — HARDENED
// ==========================

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// ---------------- SECURITY HEADERS ----------------

// Protects against clickjacking by preventing the site from being framed (X-Frame-Options: DENY)
// Prevents MIME-type sniffing by browsers (X-Content-Type-Options: nosniff)
// Controls the Referrer header sent to other sites (Referrer-Policy: no-referrer)
// Restricts use of browser features like geolocation, camera, microphone (Permissions-Policy)
// Defines which sources are allowed for content, images, styles (Content-Security-Policy)

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'");

// ---------------- SESSION HARDENING ----------------

// Starts a secure session if none exists
// cookie_httponly => protects against JS stealing session cookies
// cookie_samesite => mitigates CSRF by restricting cross-site cookie sending
// cookie_secure => should be TRUE on HTTPS to only send cookies over encrypted connection
// use_strict_mode => prevents session fixation by rejecting uninitialized session IDs

if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
        'cookie_secure' => false, // TRUE na HTTPS
        'use_strict_mode' => true,
    ]);
}

// Bind session to User‑Agent

// Binds the session to the User-Agent string to help prevent session hijacking

if (!isset($_SESSION['ua'])) {
    $_SESSION['ua'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
}

// ---------------- CSRF (PER ACTION) ----------------

// Generates a per-action CSRF token to prevent Cross-Site Request Forgery
// The token is stored in session and checked on form submission

// Verifies the CSRF token for a specific action
// Uses hash_equals to prevent timing attacks


function generate_csrf_token(string $action = 'default'): string {
    if (!isset($_SESSION['csrf'][$action])) {
        $_SESSION['csrf'][$action] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'][$action];
}

function verify_csrf_token(string $action = 'default', $token = null): bool {
    return isset($_SESSION['csrf'][$action])
        && is_string($token)
        && hash_equals($_SESSION['csrf'][$action], $token);
}

// ---------------- XSS SAFE ESCAPE ----------------

// Escapes output for HTML to prevent Cross-Site Scripting (XSS)
// Converts special characters to HTML entities

function e($s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ---------------- DB INIT ----------------

// Initializes SQLite connection with secure options
// Sets exception mode for errors, default fetch mode, and timeout
// Enables foreign key enforcement and WAL journal mode for reliability

try {
    $pdo = new PDO('sqlite:' . __DIR__ . '/database.sqlite', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT => 5,
    ]);
    $pdo->exec("PRAGMA foreign_keys = ON;");
    $pdo->exec("PRAGMA journal_mode = WAL;");
} catch (Throwable $e) {
    error_log("DB fail: ".$e->getMessage());
    exit('Database error');
}

// ---------------- SECURITY LOGGING ----------------

// Logs security-relevant events to a file safely
// Creates logs directory if missing and sets permissions
// Stores timestamp, log level, message, metadata, and client IP

function security_log($level, $msg, $meta=[]): void {
    $logdir = __DIR__.'/logs';
    if (!is_dir($logdir)) @mkdir($logdir,0750,true);

    $entry = json_encode([
        'ts' => date('c'),
        'level'=>$level,
        'msg'=>$msg,
        'meta'=>$meta,
        'ip'=>$_SERVER['REMOTE_ADDR'] ?? 'cli'
    ], JSON_UNESCAPED_SLASHES);

    @file_put_contents($logdir.'/security.log', $entry.PHP_EOL, FILE_APPEND|LOCK_EX);
}

// ---------------- PASSWORD POLICY ----------------

// Validates password strength: minimum length and must contain a digit
// Returns error message by reference if validation fails

function validate_password_strength($p,&$err=null): bool {
    if(strlen($p)<6){ $err="At least 6 chars"; return false; }
    if(!preg_match('/[0-9]/',$p)){ $err="Needs a digit"; return false; }
    return true;
}

function password_hash_secure($p): string {
    return password_hash($p, PASSWORD_ARGON2ID);
}
