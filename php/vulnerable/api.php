<?php
// api.php — INTENTIONALLY VULNERABLE 


header('Content-Type: text/plain; charset=utf-8');

try {
    // Using a separate vulnerable DB file so safe and vulnerable are not mixed.
    $db = new PDO('sqlite:users_vuln.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    // In a vulnerable demo we keep this generic; in real apps don't reveal internals.
    http_response_code(500);
    echo "DB connection error";
    exit;
}

// helper: raw POST (NO trimming, NO validation)
function raw_post($k) { return $_POST[$k] ?? ''; }

$action = $_GET['action'] ?? '';

if ($action === 'register') {
    $username = raw_post('username');
    $password = raw_post('password');

    // VULNERABILITY #1: No validation of username/password length or allowed chars.
    // VULNERABILITY #2: No password hashing — passwords are stored in plain text.
    // VULNERABILITY #3: SQL concatenation below directly injects user input into SQL.
    //   -> This allows SQL Injection.
    //
    // Example exploit: username = "attacker', 'x'); DROP TABLE users; --"
    // would cause destructive SQL when concatenated.
    try {
        $sql = "INSERT INTO users(username, password) VALUES('".$username."', '".$password."')";
        // exec() executes raw SQL built from user input — unsafe.
        $db->exec($sql);
        // VULNERABILITY #4: Reflecting raw user input in the response without escaping.
        //   This enables reflected XSS when the client inserts the response as HTML.
        echo "Registered: " . $username;
    } catch (PDOException $e) {
        // Generic DB error response
        echo "DB error";
    }
    exit;
}

if ($action === 'login') {
    session_start();
    $username = raw_post('username');
    $password = raw_post('password');

    // VULNERABILITY #5: SQL concatenation in SELECT (SQLi risk)
    // VULNERABILITY #6: Plain-text password comparison (no password_verify)
    // Example login-bypass payload: username="' OR '1'='1" (may return a row)
    try {
        $sql = "SELECT id,password FROM users WHERE username='".$username."' LIMIT 1";
        $row = $db->query($sql)->fetch(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        echo "DB error";
        exit;
    }

    if ($row && $row['password'] === $password) {
        // session not hardened (no HttpOnly/SameSite/Secure configured)
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['username'] = $username;
        echo "Login OK (vulnerable)";
    } else {
        echo "Invalid credentials";
    }
    exit;
}

http_response_code(400);
echo "Unknown action";
