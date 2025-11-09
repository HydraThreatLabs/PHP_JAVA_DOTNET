<?php
/**
 * init_db.php
 * Tworzy SQLite DB oraz tabele users i failed_logins.
 * Uruchom raz: php init_db.php
 */

try {
    $db = new PDO('sqlite:users_safe.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // tabela użytkowników
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )");

    // tabela do rate-limiting nieudanych logowań
    $db->exec("CREATE TABLE IF NOT EXISTS failed_logins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip TEXT,
        ts INTEGER
    )");

    echo "DB ready: users_safe.sqlite\n";

} catch (Exception $e) {
    echo "DB init error: " . $e->getMessage() . "\n";
    exit(1);
}
