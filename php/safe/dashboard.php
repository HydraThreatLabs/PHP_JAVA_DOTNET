<?php
require_once __DIR__ . '/config.php';

/*
|--------------------------------------------------------------------------
| ACCESS CONTROL
|--------------------------------------------------------------------------
*/
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

/*
|--------------------------------------------------------------------------
| SESSION BINDING
|--------------------------------------------------------------------------
*/
if (($_SESSION['ua'] ?? '') !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
    session_destroy();
    header("Location: index.php");
    exit;
}

$user_id = (int)$_SESSION['user_id'];
$email   = $_SESSION['email'];
$display = e($_SESSION['display_name'] ?? '');
$csrf    = generate_csrf_token();

/*
|--------------------------------------------------------------------------
| FETCH COMMENTS
|--------------------------------------------------------------------------
*/
$comments = $pdo->query(
    "SELECT u.display_name, c.comment, c.ts
     FROM comments c
     JOIN users u ON u.id = c.user_id
     ORDER BY c.ts DESC"
)->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Dashboard</title>

<!--
SECURITY NOTE:
All user-controlled output below is escaped with e().
This prevents stored and reflected XSS.
-->
<style>
body { background:#111; color:#eee; font-family:Arial; }
.box { width:450px; margin:40px auto; background:#222; padding:20px; border-radius:10px; }
.comment { background:#333; padding:6px; margin:6px 0; border-radius:6px; }
</style>
</head>

<body>
<div class="box">

<h2>Welcome, <?= $display ?: e($email) ?></h2>

<form method="POST">
<input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
<textarea name="comment" required></textarea>
<button>Post comment</button>
</form>

<hr>

<?php foreach ($comments as $c): ?>
<div class="comment">
<strong><?= e($c['display_name']) ?></strong><br>
<?= e($c['comment']) ?><br>
<small><?= date('Y-m-d H:i', $c['ts']) ?></small>
</div>
<?php endforeach; ?>

<hr>

<form method="POST" action="logout.php">
<input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
<button>Logout</button>
</form>

</div>
</body>
</html>
<?php
require_once __DIR__ . '/config.php';

/*
|--------------------------------------------------------------------------
| ACCESS CONTROL
|--------------------------------------------------------------------------
*/
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

/*
|--------------------------------------------------------------------------
| SESSION BINDING
|--------------------------------------------------------------------------
*/
if (($_SESSION['ua'] ?? '') !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
    session_destroy();
    header("Location: index.php");
    exit;
}

$user_id = (int)$_SESSION['user_id'];
$email   = $_SESSION['email'];
$display = e($_SESSION['display_name'] ?? '');
$csrf    = generate_csrf_token();

/*
|--------------------------------------------------------------------------
| FETCH COMMENTS
|--------------------------------------------------------------------------
*/
$comments = $pdo->query(
    "SELECT u.display_name, c.comment, c.ts
     FROM comments c
     JOIN users u ON u.id = c.user_id
     ORDER BY c.ts DESC"
)->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Dashboard</title>

<!--
SECURITY NOTE:
All user-controlled output below is escaped with e().
This prevents stored and reflected XSS.
-->
<style>
body { background:#111; color:#eee; font-family:Arial; }
.box { width:450px; margin:40px auto; background:#222; padding:20px; border-radius:10px; }
.comment { background:#333; padding:6px; margin:6px 0; border-radius:6px; }
</style>
</head>

<body>
<div class="box">

<h2>Welcome, <?= $display ?: e($email) ?></h2>

<form method="POST">
<input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
<textarea name="comment" required></textarea>
<button>Post comment</button>
</form>

<hr>

<?php foreach ($comments as $c): ?>
<div class="comment">
<strong><?= e($c['display_name']) ?></strong><br>
<?= e($c['comment']) ?><br>
<small><?= date('Y-m-d H:i', $c['ts']) ?></small>
</div>
<?php endforeach; ?>

<hr>

<form method="POST" action="logout.php">
<input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
<button>Logout</button>
</form>

</div>
</body>
</html>
