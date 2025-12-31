<?php
require_once __DIR__ . '/config.php';

$csrf = generate_csrf_token();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) exit('CSRF');

    if ($action === 'register') {
        $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
        $pass  = $_POST['password'] ?? '';
        $name  = trim($_POST['display_name'] ?? '');

        if (!$email) exit('Invalid email');
        if(!validate_password_strength($pass,$err)) exit($err);

        $hash = password_hash_secure($pass);
        $st=$pdo->prepare("INSERT INTO users (email, password, display_name) VALUES (?,?,?)");
        $st->execute([$email,$hash,$name]);

        echo "Registered. <a href='index.php'>Login now</a>";
        exit;
    }

    if ($action === 'login') {
        $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
        $pass  = $_POST['password'] ?? '';

        $st=$pdo->prepare("SELECT id,password,display_name FROM users WHERE email=?");
        $st->execute([$email]);
        $u=$st->fetch(PDO::FETCH_ASSOC);

        if(!$u || !password_verify($pass,$u['password'])){
            security_log('warn','failed_login',['email'=>$email]);
            exit("Invalid login");
        }

        session_regenerate_id(true);
        $_SESSION['user_id']=$u['id'];
        $_SESSION['email']=$email;
        $_SESSION['display_name']=$u['display_name'];

        header("Location: dashboard.php");
        exit;
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Login</title>
<style>
body { background:#111; color:#eee; font-family:Arial; text-align:center; }
.box { width:350px;margin:50px auto;background:#222;padding:20px;border-radius:8px; }
input { padding:8px;width:90%;margin:5px; }
button { padding:8px 20px;margin-top:10px; }
</style>
</head>
<body>

<div class="box">
<h2>Login / Register</h2>

<form method="POST">
    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
    <input name="email" placeholder="Email" required>
    <input name="password" type="password" placeholder="Password" required>
    <button name="action" value="login">Login</button>
</form>

<hr>

<form method="POST">
    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
    <input name="display_name" placeholder="Display Name">
    <input name="email" placeholder="Email" required>
    <input name="password" type="password" placeholder="Password" required>
    <button name="action" value="register">Register</button>
</form>

</div>
</body>
</html>
