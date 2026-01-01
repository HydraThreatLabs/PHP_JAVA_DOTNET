<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$DB_FILE = __DIR__ . '/users_safe.sqlite';
$ENABLE_APP_LOG = false;  // wyłącz logi, żeby nie mieszały

try {
    $db = new PDO('sqlite:' . $DB_FILE);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('PRAGMA busy_timeout = 5000');
    echo "DB connected OK\n";

    $stmt = $db->prepare('SELECT * FROM users LIMIT 1');
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    var_dump($row);

} catch (Throwable $e) {
    echo "PDO Error: " . $e->getMessage() . "\n";
}
