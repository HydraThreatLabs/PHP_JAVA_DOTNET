<?php
require_once __DIR__.'/config.php';

header('Content-Type: application/json');

// Simple RATE-LIMIT (A04: Rate limiting abuse)
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$key = "rl_$ip";
$_SESSION[$key] = ($_SESSION[$key] ?? 0) + 1;
if ($_SESSION[$key] > 100){
    http_response_code(429);
    echo json_encode(["error"=>"Too many requests"]);
    exit;
}

echo json_encode(["status"=>"OK"]);
