<?php
require_once __DIR__.'/config.php';
if(!verify_csrf_token($_POST['csrf_token'] ?? '')){
    exit("CSRF");
}
session_unset();
session_destroy();
header("Location: index.php");
exit;
?>
