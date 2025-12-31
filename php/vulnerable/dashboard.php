<?php
session_start();

// ❌ słaby auth – tylko sprawdzenie zmiennej
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$db = new PDO('sqlite:users_vuln.sqlite');
$comments = $db->query("
    SELECT u.username, c.comment
    FROM comments c
    LEFT JOIN users u ON u.id = c.user_id
")->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html>
<body>

<h1>Hello <?= $_SESSION['username'] ?></h1>

<form id="c">
<textarea name="comment"></textarea>
<button>Add comment</button>
</form>

<pre id="o"></pre>

<hr>

<?php foreach ($comments as $c): ?>
<p>
<b><?= $c['username'] ?></b>:
<?= $c['comment'] ?>
</p>
<?php endforeach; ?>

<a href="logout.php">Logout</a>

<script>
c.onsubmit = async e => {
    e.preventDefault();
    const fd = new FormData(c);
    const res = await fetch('api.php?action=comment', {
        method:'POST',
        body:fd
    });
    o.textContent = await res.text();
    location.reload();
};
</script>

</body>
</html>
