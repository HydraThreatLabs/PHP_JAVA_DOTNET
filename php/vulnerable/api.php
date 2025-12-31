<?php
session_start();
header('Content-Type: text/plain; charset=utf-8');

$db = new PDO('sqlite:users_vuln.sqlite');

/*
❌ Brak:
- prepared statements
- filtrowania danych
- obsługi błędów
*/

$action = $_GET['action'] ?? '';

function p($k) {
    return $_POST[$k] ?? '';
}

/* ================= REGISTER ================= */
if ($action === 'register') {
    $u = p('username');
    $p = p('password');

    // ❌ SQL Injection:
    // username: anna'); DROP TABLE users; --
    // ❌ Plaintext password
    $sql = "INSERT INTO users(username,password) VALUES('$u','$p')";
    $db->exec($sql);

    echo "Registered: $u";
    exit;
}

/* ================= LOGIN ================= */
if ($action === 'login') {
    $u = p('username');
    $p = p('password');

    // ❌ SQL Injection:
    // username: ' OR 1=1 --
    $sql = "SELECT id,password FROM users WHERE username='$u' LIMIT 1";
    $row = $db->query($sql)->fetch(PDO::FETCH_ASSOC);

    // ❌ brak password_hash / verify
    if ($row && $row['password'] === $p) {
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['username'] = $u;
        echo "Login OK";
    } else {
        echo "Invalid credentials";
    }
    exit;
}

/* ================= COMMENT ================= */
if ($action === 'comment') {
    $uid = $_SESSION['user_id'] ?? 0;
    $c = p('comment');

    // ❌ brak auth check
    // ❌ XSS:
    // <script>alert(1)</script>
    $sql = "INSERT INTO comments(user_id,comment) VALUES($uid,'$c')";
    $db->exec($sql);

    echo "Comment added";
    exit;
}

echo "Unknown action";
