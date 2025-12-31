<?php
// init_db.php — pełne utworzenie bazy danych
$dbFile = __DIR__ . '/database.sqlite';
if(file_exists($dbFile)) unlink($dbFile);

$pdo = new PDO('sqlite:' . $dbFile);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec("PRAGMA foreign_keys = ON;");

// Tabela users
$pdo->exec("
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT,
    avatar TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
");

// Tabela comments
$pdo->exec("
CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    comment TEXT NOT NULL,
    ts INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
");

echo "DATABASE INITIALIZED SUCCESSFULLY\n";
?>
