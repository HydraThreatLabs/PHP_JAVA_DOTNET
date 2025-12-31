<?php session_start(); ?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>VULNERABLE APP</title>
<style>
body { font-family: Arial; margin:20px; }
input, textarea { display:block; margin:6px 0; width:300px; }
pre { background:#eee; padding:10px; }
</style>
</head>
<body>

<h1>VULNERABLE AUTH APP</h1>

<h2>Register</h2>
<form id="reg">
<input name="username">
<input name="password">
<button>Register</button>
</form>
<pre id="r"></pre>

<h2>Login</h2>
<form id="log">
<input name="username">
<input name="password">
<button>Login</button>
</form>
<pre id="l"></pre>

<script>
reg.onsubmit = async e => {
    e.preventDefault();
    const fd = new FormData(reg);
    const res = await fetch('api.php?action=register', {
        method:'POST',
        body:fd
    });
    r.textContent = await res.text();
};

log.onsubmit = async e => {
    e.preventDefault();
    const fd = new FormData(log);
    const res = await fetch('api.php?action=login', {
        method:'POST',
        body:fd
    });
    const t = await res.text();
    l.textContent = t;
    if (t.includes('OK')) location = 'dashboard.php';
};
</script>

</body>
</html>
