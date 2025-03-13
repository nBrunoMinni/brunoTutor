<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);
session_start();
session_regenerate_id(true);
require_once(__DIR__ . '/../../config/config.php');
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    if (!in_array($_SERVER['HTTP_HOST'], ['localhost', '127.0.0.1'])) {
        header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
        exit;
    }
}

?>

<!DOCTYPE html>
<html>

<head>
    <title>BrunoTutor.com - TOS</title>
    <link href="style.css" rel="stylesheet">
    <link href="sucStyle.css" rel="stylesheet">

    <link rel="icon" type="image/x-icon" href="home.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1">

</head>

<body>
    <main class="main">
        <div class="success-container">
            <h1>Terms of service</h1>
            <p>The use of this site is limited to tutoring.</p>
            <p>Tutors must obey all local laws regarding employment and transactions.</p>
            <p>The website is not responsible for any agreements, disputes, or interactions between tutors and students.</p>
            <p>Users assume full responsibility for their actions while using this site.</p>
            <p>By using this site, you agree to these terms.</p>

            <h1>Report a problem</h1>
            <p>Please report bugs or misuse of the site to our email: </p>
            <b>hello@brunotutor.com</b><br>

            <a href="https://www.brunotutor.com" class="btn">Return home</a>
        </div>
    </main>

    <footer class="footer">
        <small><a href="https://www.brunotutor.com">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
        <small><a href="https://www.brunotutor.com/regTutor.php">Create page</a> • <a href="https://www.brunotutor.com/tos.php">Terms of service</a></small>
    </footer>
</body>

</html>