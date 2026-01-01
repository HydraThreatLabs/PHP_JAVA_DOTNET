<?php
require_once __DIR__.'/config.php';

// CSRF token dla 'logout'
if (!verify_csrf_token('logout', $_POST['csrf_token'] ?? '')) {
    exit("CSRF");
}

// destroy session
session_unset();
session_destroy();
header("Location: index.php");
exit;
