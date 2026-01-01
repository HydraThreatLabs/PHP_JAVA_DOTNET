<?php
require_once __DIR__.'/config.php';


// Check if the user is logged in
// If not, redirect to login page
// Prevents unauthorized access to the dashboard

if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

// UA bind

// Bind the session to the browser's User-Agent
// Helps prevent session hijacking:
//   If an attacker steals a session cookie and tries to use it from a different browser or device, 
//   the session will be invalidated
// Session hijacking = when someone steals your session ID (cookie) to impersonate you

if ($_SESSION['ua'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
    session_destroy();
    header("Location: index.php");
    exit;
}

$user_id = (int)$_SESSION['user_id'];
$email   = $_SESSION['email'] ?? '';
$display = e($_SESSION['display_name'] ?? '');

// CSRF

// Generate per-action CSRF tokens
// CSRF (Cross-Site Request Forgery) = an attack where a malicious site makes your browser perform actions on another site 
// without your consent (like changing password, posting comments)
// Using unique tokens per action prevents such attacks

$csrf_comment = generate_csrf_token('comment');
$csrf_avatar  = generate_csrf_token('avatar');
$csrf_pass    = generate_csrf_token('password');
$csrf_logout  = generate_csrf_token('logout');

// Upload dirs

// Ensure upload directories exist with proper permissions
// Public directory: readable by web server, group-executable (0750)
// Private directory: only accessible by owner (0700)
// Prevents unauthorized users or scripts from writing to uploads or reading private files

$public_uploads  = __DIR__.'/uploads';
$private_uploads = __DIR__.'/private_uploads';

foreach ([$public_uploads => 0750, $private_uploads => 0700] as $dir => $perm) {
    if (!is_dir($dir) && !mkdir($dir, $perm, true)) {
        exit("Storage error");
    }
}

/* ================= AVATAR UPLOAD ================= */

// Validate CSRF token before processing file upload
// Restrict file size to prevent DoS attacks
// Validate MIME type to allow only PNG or JPEG images
// Use imagecreatefromstring to ensure file is a real image (prevents uploading malicious scripts)
// Store private copy and copy to public directory (for web access)
// This protects against:
//   - CSRF (without token, upload is blocked)
//   - Arbitrary file upload / remote code execution
//   - Oversized files / resource exhaustion

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {

    if (!verify_csrf_token('avatar', $_POST['csrf_token'] ?? '')) exit("CSRF");

    if ($_FILES['avatar']['size'] > 2 * 1024 * 1024) exit("Too big");

    $mime = mime_content_type($_FILES['avatar']['tmp_name']);
    if (!in_array($mime, ['image/png','image/jpeg'], true)) exit("Bad type");

    $img = @imagecreatefromstring(file_get_contents($_FILES['avatar']['tmp_name']));
    if (!$img) exit("Invalid image");

    $priv = $private_uploads . "/avatar_{$user_id}.png";
    $pub  = $public_uploads  . "/avatar_{$user_id}.png";

    imagepng($img, $priv);
    imagedestroy($img);

    copy($priv, $pub);
}

/* ================= COMMENTS ================= */

// Validate CSRF token for comment submission
// Trim comment and limit length to 200 characters
// Only allow one comment per user in this simple example
// Escaping output when displaying prevents XSS attacks (stored XSS)
// This protects against:
//   - CSRF
//   - XSS (by escaping later)
//   - Comment spam or abuse (limited to 1 per user)

if (isset($_POST['comment'])) {

    if (!verify_csrf_token('comment', $_POST['csrf_token'] ?? '')) exit("CSRF");

    $clean = substr(trim($_POST['comment']), 0, 200);

    $chk = $pdo->prepare("SELECT COUNT(*) FROM comments WHERE user_id=?");
    $chk->execute([$user_id]);

    if ($chk->fetchColumn() == 0) {
        $pdo->prepare(
            "INSERT INTO comments (user_id, comment, ts) VALUES (?,?,?)"
        )->execute([$user_id, $clean, time()]);
    }
}

/* ================= PASSWORD CHANGE ================= */

// Validate CSRF token for password change
// Verify old password matches the database
// Validate new password strength (min 6 chars, at least 1 number)
// Use secure Argon2id hash to store password
// Protects against:
//   - CSRF (prevents unauthorized password changes)
//   - Weak passwords (enforces policy)
//   - Password leaks if database is compromised (secure hashing)

if (isset($_POST['old_password'], $_POST['new_password'])) {

    if (!verify_csrf_token('password', $_POST['csrf_token'] ?? '')) exit("CSRF");

    $st = $pdo->prepare("SELECT password FROM users WHERE id=?");
    $st->execute([$user_id]);
    $row = $st->fetch();

    if (!$row || !password_verify($_POST['old_password'], $row['password'])) {
        exit("Old password wrong");
    }

    if (!validate_password_strength($_POST['new_password'], $err)) exit($err);

    $pdo->prepare("UPDATE users SET password=? WHERE id=?")
        ->execute([password_hash_secure($_POST['new_password']), $user_id]);
}

/* ================= FETCH COMMENTS ================= */
// Fetch comments from database with JOIN to get user display names
// Later displayed with escaping (e()) to prevent XSS
// Protects against:
//   - XSS (when echoing $c['comment'] or display name)
//   - SQL injection is mitigated because prepared statements are used for insertion

$comments = $pdo->query("
    SELECT users.display_name, comments.comment, comments.ts
    FROM comments
    JOIN users ON users.id = comments.user_id
    ORDER BY comments.ts DESC
")->fetchAll();

/* ================= AVATAR CHECK ================= */

// Check if avatar file exists for the user
// When displaying, append ?t=timestamp to force browser to reload updated image
// Protects against showing stale avatars or non-existent files

$avatar_path = "uploads/avatar_{$user_id}.png";
$has_avatar  = file_exists(__DIR__ . "/$avatar_path");
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Dashboard</title>
<style>
body { background:#111;color:#eee;font-family:Arial;text-align:center; }
.box { margin:20px auto;padding:20px;width:450px;background:#222;border-radius:10px; }
.avatar { width:120px;height:120px;border-radius:50%;border:3px solid #444;object-fit:cover; }
textarea { width:100%;height:70px;padding:8px;border-radius:6px; }
.comment { background:#333;margin:6px;padding:6px;border-radius:6px;text-align:left; }
</style>
</head>
<body>
<div class="box">

<h2>Welcome, <?php echo $display ?: e($email); ?></h2>

<?php if ($has_avatar): ?>
    <img src="<?php echo $avatar_path; ?>?t=<?php echo time(); ?>" class="avatar">
<?php endif; ?>

<hr>

<h3>Upload avatar</h3>
<form method="POST" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="<?php echo e($csrf_avatar); ?>">
    <input type="file" name="avatar" accept="image/png,image/jpeg" required>
    <button>Upload</button>
</form>

<hr>

<h3>Post a Comment</h3>
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo e($csrf_comment); ?>">
    <textarea name="comment" required></textarea>
    <button>Post</button>
</form>

<h3>Comments</h3>
<?php foreach ($comments as $c): ?>
<div class="comment">
    <strong><?php echo e($c['display_name']); ?>:</strong><br>
    <?php echo e($c['comment']); ?><br>
    <small><?php echo date("Y-m-d H:i", $c['ts']); ?></small>
</div>
<?php endforeach; ?>

<hr>

<h3>Change Password</h3>
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo e($csrf_pass); ?>">
    <input type="password" name="old_password" required>
    <input type="password" name="new_password" required>
    <button>Change</button>
</form>

<hr>

<form method="POST" action="logout.php">
    <input type="hidden" name="csrf_token" value="<?php echo e($csrf_logout); ?>">
    <button>Logout</button>
</form>

</div>
</body>
</html>
