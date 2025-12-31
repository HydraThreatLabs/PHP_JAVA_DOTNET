<?php
require_once __DIR__ . '/config.php';

$csrf_token = generate_csrf_token();
$message = '';
$show_form = false;
$token = $_GET['token'] ?? '';

if ($token !== '') {
    $stmt = $pdo->prepare('SELECT * FROM password_resets WHERE token = ? AND expires > ?');
    $stmt->execute([$token, time()]);
    $reset = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($reset) {
        $show_form = true;

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (!verify_csrf_token($_POST['csrf_token'] ?? '')) exit('CSRF token mismatch');

            $password = $_POST['password'] ?? '';
            $pw_err = null;
            if (!validate_password_strength($password, $pw_err)) {
                $message = 'Password policy: ' . $pw_err;
            } else {
                $hash = password_hash_secure($password);
                $pdo->prepare('UPDATE users SET password = ? WHERE id = ?')
                    ->execute([$hash, $reset['user_id']]);

                // usuń token
                $pdo->prepare('DELETE FROM password_resets WHERE token = ?')->execute([$token]);
                $message = 'Password has been reset successfully. <a href="index.php">Login</a>';
                security_log('info','password_reset_done',['user_id'=>$reset['user_id']]);
                $show_form = false;
            }
        }
    } else {
        $message = 'Invalid or expired token';
    }
} else {
    $message = 'Missing token';
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Reset Password</title>
</head>
<body>
<h2>Reset Password</h2>
<?php if($show_form): ?>
<form method="POST">
<input type="hidden" name="csrf_token" value="<?php echo e($csrf_token); ?>">
<input type="password" name="password" placeholder="New password" required>
<button type="submit">Reset Password</button>
</form>
<?php endif; ?>
<p><?php echo $message; ?></p>
<p><a href="index.php">Back to login</a></p>
</body>
</html>
