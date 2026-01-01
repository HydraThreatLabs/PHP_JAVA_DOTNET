<?php
require_once __DIR__ . '/config.php';

$csrf_token = generate_csrf_token();
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) exit('CSRF token mismatch');

    $email = strtolower(trim($_POST['email'] ?? ''));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = 'Invalid email';
    } else {
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $token = bin2hex(random_bytes(32));
            $expires = time() + 3600; // 1h

            $pdo->prepare('INSERT INTO password_resets (user_id, token, expires) VALUES (?, ?, ?)')
                ->execute([$user['id'], $token, $expires]);

            // Tutaj wysyłamy email (w prod, użyj PHPMailer lub mail())
            $reset_link = "http://yourdomain.com/reset.php?token=$token";
            $message = "Password reset link (simulate sending email): <a href='$reset_link'>$reset_link</a>";
            security_log('info','password_reset_requested',['email'=>$email]);
        } else {
            // nie ujawniamy, że email nie istnieje
            $message = 'If this email exists, a reset link was sent';
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Forgot Password</title>
</head>
<body>
<h2>Forgot Password</h2>
<form method="POST">
<input type="hidden" name="csrf_token" value="<?php echo e($csrf_token); ?>">
<input type="email" name="email" placeholder="Enter your email" required>
<button type="submit">Send Reset Link</button>
</form>
<p><?php echo $message; ?></p>
<p><a href="index.php">Back to login</a></p>
</body>
</html>
