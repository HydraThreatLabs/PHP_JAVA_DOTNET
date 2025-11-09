<?php
// init_db.php for vulnerable demo
// Comments: this schema is intentionally weak (plain passwords, no UNIQUE constraint).

try {
    // Use a different DB file for the vulnerable demo
    $db = new PDO('sqlite:users_vuln.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // VULNERABILITY: username is NOT UNIQUE, and password is stored as plain text.
    // This allows duplicate accounts and makes password leaks immediately useful.
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )");

    echo "DB ready: users_vuln.sqlite\n";
} catch (Exception $e) {
    echo "DB init error: " . $e->getMessage() . "\n";
    exit(1);
}
