<?php
/**
 * api.php — hardened authentication endpoint with application logging
 *
 * Goals & design summary (short):
 *  - Keep authentication logic server-side (trust nothing from client).
 *  - Use prepared statements to prevent SQL injection.
 *  - Use password_hash/password_verify for secure password storage.
 *  - Provide rate-limiting to slow brute-force attacks (failed_logins table).
 *  - Use a robust, failure-tolerant logging mechanism:
 *      - logs/auth.log receives structured app events (login/register/failures)
 *      - logging never causes the API to break (fail silently with server-side error_log)
 *  - Add SQLite pragmas to avoid transient "database is locked" (busy_timeout)
 *  - Provide safe session cookie parameters (httponly/samesite/secure when HTTPS)
 *
 * IMPORTANT deployment steps (see bottom of file for commands)
 */

/* -------------------- Configuration -------------------- */

// ini_set('display_errors', 1);  (debiuger in case of errors)
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);

// Toggle application-level logging to a file. If false, only system error_log is used.
$ENABLE_APP_LOG = true;

// Application log file (relative to this directory)
$APP_LOG_DIR = __DIR__ . '/logs';
$APP_LOG_FILE = $APP_LOG_DIR . '/auth.log';

// SQLite DB file
$DB_FILE = __DIR__ . '/users_safe.sqlite';

// Set to true to attempt WAL mode. If WAL cannot be enabled due to permissions, code will continue without it.
// WAL improves concurrency but creates -wal/-shm files which require write permissions on the directory.
$TRY_ENABLE_WAL = true;

/* -------------------- HTTP headers -------------------- */
// Keep responses plain text for the API (client JS expects plain text)
header('Content-Type: text/plain; charset=utf-8');

// Minimal security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer-when-downgrade');
header('Permissions-Policy: interest-cohort=()'); // opt-out of cohorting

/* -------------------- Helper functions -------------------- */

/**
 * Safe logger that writes to an application log file without breaking the app.
 *
 * Mechanism:
 *  - Ensures logs directory exists (attempts to create it).
 *  - Opens file with append mode, acquires LOCK_EX (advisory lock), writes, flushes, releases lock.
 *  - All file errors are suppressed and cause a server-side error_log() call; they do NOT throw to clients.
 *
 * Why this is secure / helpful:
 *  - Keeps auth events in a dedicated file for monitoring/forensics.
 *  - Uses exclusive locks to avoid concurrent write corruption.
 *  - Fails silently (non-fatal) to avoid denial-of-service if logging can't write due to perms/FS issues.
 */
function app_log(string $msg) {
    global $ENABLE_APP_LOG, $APP_LOG_DIR, $APP_LOG_FILE;

    // If application logging disabled by config, do nothing.
    if (empty($ENABLE_APP_LOG)) return;

    // Ensure directory exists (best-effort). Suppress warnings.
    if (!is_dir($APP_LOG_DIR)) {
        @mkdir($APP_LOG_DIR, 0700, true);
    }

    // Build the log line (ISO datetime + message)
    $line = date('c') . ' - ' . $msg . PHP_EOL;

    // Open file for append; suppress warnings to avoid exposing to client
    $fp = @fopen($APP_LOG_FILE, 'a');
    if ($fp === false) {
        // Fail silently for client; record to system logs for operator
        error_log("api.php: app_log fopen failed for $APP_LOG_FILE");
        return;
    }

    // Use flock to avoid interleaving writes between processes.
    if (@flock($fp, LOCK_EX)) {
        @fwrite($fp, $line);
        @fflush($fp);
        @flock($fp, LOCK_UN);
    } else {
        // If flock fails, best-effort write without lock
        @fwrite($fp, $line);
    }

    @fclose($fp);
}

/**
 * Helper: get IP in a simple way. If you're behind a trusted proxy,
 * replace with robust parsing of X-Forwarded-For with whitelist.
 */
function get_remote_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Safe multibyte-aware strlen: use mb_strlen if available, otherwise fallback.
 */
function safe_strlen(string $s): int {
    if (function_exists('mb_strlen')) return mb_strlen($s);
    return strlen($s);
}

/* -------------------- Database connection -------------------- */

// Create PDO connection to SQLite with exception mode
try {
    $db = new PDO('sqlite:' . $DB_FILE);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Busy timeout: if DB locked briefly by another process, wait up to X ms instead of failing immediately.
    // This helps when multiple Apache workers access a single-file DB.
    $db->exec('PRAGMA busy_timeout = 5000;'); // wait up to 5 seconds

    // Try enabling WAL as optional optimization to improve concurrency.
    if (!empty($TRY_ENABLE_WAL)) {
        // WAL can fail (permission issues). Wrap in try/catch and log only on server logs (not to client).
        try {
            $res = $db->query('PRAGMA journal_mode = WAL');
            // optional: could check $res->fetchColumn()
        } catch (Throwable $e) {
            // WAL failed; do not treat as fatal; log for operator
            error_log('api.php: could not enable WAL: ' . $e->getMessage());
            app_log('WAL enable failed: ' . $e->getMessage());
        }
    }
} catch (Throwable $e) {
    // If DB can't be opened at all, log and return neutral server error.
    error_log('api.php: DB open failed: ' . $e->getMessage());
    http_response_code(500);
    echo "Server error";
    exit;
}

/* -------------------- Session hardening -------------------- */

// Determine HTTPS to set secure cookie flag when possible
$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);

// Strict session handling + cookie params set BEFORE session_start.
ini_set('session.use_strict_mode', 1);
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',      // set in production to your domain
    'secure' => $secure,
    'httponly' => true,
    'samesite' => 'Lax'  // reasonable default; consider 'Strict' if app supports it
]);

/* -------------------- Rate-limiting config -------------------- */

$MAX_FAILS = 5;
$WINDOW_SEC = 15 * 60; // 15 minutes sliding window

/* -------------------- Router / main logic -------------------- */

$action = $_GET['action'] ?? '';

if ($action === 'register') {
    // Server-side validation is authoritative
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        http_response_code(400);
        echo "Username and password required";
        exit;
    }
    if (safe_strlen($username) < 3 || safe_strlen($username) > 50) {
        http_response_code(400);
        echo "Username length invalid (3-50)";
        exit;
    }
    if (safe_strlen($password) < 6) {
        http_response_code(400);
        echo "Password too short (min 6 chars)";
        exit;
    }

    // Use Argon2id if available, otherwise PASSWORD_DEFAULT (bcrypt on many PHPs).
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    $hash = password_hash($password, $algo);

    try {
        $stmt = $db->prepare('INSERT INTO users(username, password, created_at) VALUES(:u, :p, :ts)');
        $stmt->execute([':u' => $username, ':p' => $hash, ':ts' => time()]);

        // App-level log (for monitoring / forensic)
        app_log("register success: username=$username ip=" . get_remote_ip());

        // Also place a short operator-visible line in system logs
        error_log("api.php: register success for $username from " . get_remote_ip());

        echo "Registered OK";
    } catch (PDOException $e) {
        // Log internal details to operator logs (not to client)
        error_log('api.php: DB error on register: ' . $e->getMessage());
        app_log('DB error on register: ' . $e->getMessage());

        if (stripos($e->getMessage(), 'UNIQUE') !== false) {
            http_response_code(409);
            echo "Username not available";
        } else {
            http_response_code(500);
            echo "Server error";
        }
    }
    exit;
}

if ($action === 'login') {
    // Start session after cookie params set above
    session_start();

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $ip = get_remote_ip();

    if ($username === '' || $password === '') {
        http_response_code(400);
        echo "Username and password required";
        exit;
    }

    // Rate-limiting check: sliding window count
    try {
        $win = time() - $WINDOW_SEC;
        $stmt = $db->prepare('SELECT COUNT(*) FROM failed_logins WHERE (username = :u OR ip = :ip) AND ts > :win');
        $stmt->execute([':u' => $username, ':ip' => $ip, ':win' => $win]);
        $fails = (int)$stmt->fetchColumn();
    } catch (Throwable $e) {
        // If this fails, don't block logins — log the error and continue with fails=0
        error_log('api.php: failed_logins select failed: ' . $e->getMessage());
        app_log('failed_logins select failed: ' . $e->getMessage());
        $fails = 0;
    }

    if ($fails >= $MAX_FAILS) {
        http_response_code(429);
        echo "Too many failed attempts. Try again later.";
        exit;
    }

    // Fetch user row
    try {
        $stmt = $db->prepare('SELECT id, password FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        error_log('api.php: user select failed: ' . $e->getMessage());
        app_log('user select failed: ' . $e->getMessage());
        http_response_code(500);
        echo "Server error";
        exit;
    }

    // Verify password — password_verify uses safe comparison
    if (!$row || !password_verify($password, $row['password'])) {
        // Record failure (best-effort)
        try {
            $ins = $db->prepare('INSERT INTO failed_logins(username, ip, ts) VALUES(:u, :ip, :ts)');
            $ins->execute([':u' => $username, ':ip' => $ip, ':ts' => time()]);
        } catch (Throwable $e) {
            // If insert fails, log to system log and continue; not fatal.
            error_log('api.php: failed_log insert failed: ' . $e->getMessage());
            app_log('failed_log insert failed: ' . $e->getMessage());
        }

        app_log("login failed: username=$username ip=$ip");
        error_log("api.php: login failed for $username from $ip");

        http_response_code(401);
        echo "Invalid credentials";
        exit;
    }

    // Success: clear fail counters (best-effort)
    try {
        $del = $db->prepare('DELETE FROM failed_logins WHERE username = :u OR ip = :ip');
        $del->execute([':u' => $username, ':ip' => $ip]);
    } catch (Throwable $e) {
        error_log('api.php: failed_log delete failed: ' . $e->getMessage());
        app_log('failed_log delete failed: ' . $e->getMessage());
    }

    // Prevent session fixation
    session_regenerate_id(true);
    $_SESSION['user_id'] = $row['id'];
    $_SESSION['username'] = $username;

    app_log("login success: username=$username ip=$ip uid={$row['id']}");
    error_log("api.php: login success for $username from $ip (uid={$row['id']})");

    echo "Login OK";
    exit;
}

/* Unknown action */
http_response_code(400);
echo "Unknown action";
