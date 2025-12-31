<?php
try {
    $db = new PDO('sqlite:users_vuln.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // ❌ brak UNIQUE na username
    // ❌ brak hashów haseł
    $db->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ");

    // ❌ brak foreign key
    // ❌ brak ograniczeń długości
    $db->exec("
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            comment TEXT
        )
    ");

    echo "VULNERABLE DB READY\n";
} catch (Exception $e) {
    echo "DB ERROR";
}
