<?php
require_once __DIR__.'/config.php';


// Generate CSRF tokens for login and register forms
// Protects against CSRF attacks:
//   Without these tokens, a malicious site could trick a logged-out user into submitting
//   login or registration requests on your site


$csrf_login    = generate_csrf_token('login');
$csrf_register = generate_csrf_token('register');

// Handle form submissions securely
// - Trim and normalize email
// - Extract password and display name
// Validates input before interacting with database


if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $action = $_POST['action'] ?? '';
    $email  = strtolower(trim($_POST['email'] ?? ''));
    $pass   = $_POST['password'] ?? '';
    $display_name = trim($_POST['display_name'] ?? '');

    if ($action === 'register') {
        if(!verify_csrf_token('register', $_POST['csrf_token'] ?? '')) exit('CSRF');
        if (!filter_var($email,FILTER_VALIDATE_EMAIL)) exit('Invalid email');
        if(!validate_password_strength($pass,$err)) exit($err);

        $hash = password_hash_secure($pass);
        $st=$pdo->prepare("INSERT INTO users (email,password,display_name) VALUES (?,?,?)");
        $st->execute([$email,$hash,$display_name]);

        echo "Registered. <a href='index.php'>Login now</a>";
        exit;
    }

    if ($action === 'login') {
        if(!verify_csrf_token('login', $_POST['csrf_token'] ?? '')) exit('CSRF');
        if (!filter_var($email,FILTER_VALIDATE_EMAIL)) exit('Invalid email');

        $st=$pdo->prepare("SELECT id,password,display_name FROM users WHERE email=?");
        $st->execute([$email]);
        $u=$st->fetch();

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
<title>Login / Register</title>
<style>
body { background:#111; color:#eee; font-family:Arial; text-align:center; }
.box { width:350px;margin:50px auto;background:#222;padding:20px;border-radius:8px; }
input { padding:8px;width:90%;margin:5px; }
button { padding:8px 20px;margin-top:10px; }
</style>
</head>
<body>
<div class="box">

<h2>Login</h2>
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo e($csrf_login); ?>">
    <input name="email" placeholder="Email" required>
    <input name="password" type="password" placeholder="Password" required>
    <button name="action" value="login">Login</button>
</form>


<hr>



<h2>Register</h2>
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo e($csrf_register); ?>">
    <input name="display_name" placeholder="Display Name">
    <input name="email" placeholder="Email" required>
    <input name="password" type="password" placeholder="Password" required>
    <button name="action" value="register">Register</button>
</form>

</div>
</body>
</html>





<?php
/*
============================================================
SECURITY SUMMARY – WHY THIS APP IS SAFE
============================================================

--------------------
SQL INJECTION
--------------------

- PDO prepared statements (prepare + execute)
  User input is never concatenated into SQL queries.
  Input is treated strictly as data, not executable SQL.

- No dynamic SQL construction
  No queries like:
    "SELECT * FROM users WHERE email='$email'"

- Explicit type casting
  Example:
    $user_id = (int)$_SESSION['user_id'];

RESULT:
SQL Injection attacks are blocked.


--------------------
XSS (Cross-Site Scripting)
--------------------

- Output escaping with e()
  Function e() uses htmlspecialchars().
  It converts HTML/JS into safe text.

  Example:
    <script>alert(1)</script>
  becomes:
    &lt;script&gt;alert(1)&lt;/script&gt;

- Escape on output, not on input
  Raw data is stored.
  Escaping happens only when displaying content.

- All user-controlled data is escaped
  Comments, display names, emails.

- Content Security Policy (CSP)
  Prevents execution of injected scripts.

RESULT:
Stored and reflected XSS are mitigated.


--------------------
SESSION HIJACKING
--------------------

- HttpOnly session cookies
  JavaScript cannot access session cookies.

- User-Agent binding
  Session is invalidated if browser fingerprint changes.

- session_regenerate_id()
  Prevents session fixation after login.


--------------------
CSRF (Cross-Site Request Forgery)
--------------------

- Per-action CSRF tokens
  Separate tokens for login, register, comment, avatar, password.

- Cryptographically secure tokens
  Generated using random_bytes().

RESULT:
CSRF attacks are blocked.


--------------------
FILE UPLOAD SECURITY
--------------------

- MIME type validation
  Only PNG and JPEG are allowed.

- Image decoding validation
  imagecreatefromstring() ensures real image content.

- Private file storage
  Files are processed outside public directory first.

RESULT:
Malicious file uploads are prevented.


--------------------
IMPORTANT NOTE
--------------------

If <script>alert()</script> appears as text
and does NOT execute, this is correct behavior.
It means XSS is successfully neutralized.

============================================================
*/