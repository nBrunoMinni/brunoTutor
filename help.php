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

// Detect language from subdomain
$httpHost = $_SERVER['HTTP_HOST'];

if (preg_match('/^([a-z]{2})\.brunotutor\.com/', $httpHost, $matches)) {
    $detectedLang = $matches[1];

    $tempDbc = new mysqli($host, $username, $password, $database);
    if (!$tempDbc->connect_error) {
        $tempDbc->set_charset("utf8mb4");
        $checkLang = $tempDbc->prepare("SELECT lang FROM UILanguage WHERE lang = ? LIMIT 1");
        $checkLang->bind_param('s', $detectedLang);
        $checkLang->execute();
        $langResult = $checkLang->get_result();

        if ($langResult && $langResult->num_rows === 1) {
            $_SESSION['lang'] = $detectedLang;
        } else {
            $_SESSION['lang'] = 'en'; // Fallback English
        }
        $checkLang->close();
        $tempDbc->close();
    }
} else {

    if (!isset($_SESSION['lang'])) {
        $_SESSION['lang'] = 'en';
    }
}

$userLang = $_SESSION['lang'];

$dbc = new mysqli($host, $username, $password, $database);
if ($dbc->connect_error) {
    die("Database connection failed: " . $dbc->connect_error);
}
$dbc->set_charset("utf8mb4");

$userLang = $_SESSION['lang'] ?? 'en';

// Fetch UI language strings
$stmt = $dbc->prepare("SELECT * FROM UILanguage WHERE lang = ? LIMIT 1");
$stmt->bind_param('s', $userLang);
$stmt->execute();
$result = $stmt->get_result();

if ($result && $result->num_rows === 1) {
    $lang = $result->fetch_assoc();
} else {
    // Fallback English
    $stmt = $dbc->prepare("SELECT * FROM UILanguage WHERE lang = 'en' LIMIT 1");
    $stmt->execute();
    $result = $stmt->get_result();
    $lang = $result->fetch_assoc();
}
$stmt->close();

// Fetch available languages
$langStmt = $dbc->query("SELECT lang, UILanguage FROM UILanguage ORDER BY lang ASC");
$availableLanguages = [];
while ($langRow = $langStmt->fetch_assoc()) {
    $availableLanguages[] = $langRow;
}

// HTML escaping
function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}
?>
<!DOCTYPE html>
<html>

<head>
    <title>BrunoTutor.com - Cal.com</title>
    <link href="style.css" rel="stylesheet">
    <link href="sucStyle.css" rel="stylesheet">
    <link rel="icon" type="image/x-icon" href="home.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>

<body>
    <main class="main">
        <div class="success-container">
            <h1><?= e($lang['connectCal']); ?></h1>
            <p><?= e($lang['usesCal']); ?></p>
            <ol style="text-align: left;">
                <li><?= e($lang['cal1']); ?></li>
                <li><?= e($lang['cal2']); ?></li>
                <li><?= e($lang['cal3']); ?></li>
                <li><?= e($lang['cal4']); ?></li>
            </ol>
            <a href="index.php" class="btn"><?= e($lang['returnHome']); ?></a>
        </div>
    </main>
    <footer class="footer">
        <small><a href="index.php">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
        <small><a href="editTutor.php"><?= e($lang['login']); ?></a> / <a href="tos.php"><?= e($lang['report']); ?></a></small>
        <br>
        <small>
            <select id="langSelect" onchange="changeLanguage()" style="margin-top: 10px; padding: 5px; border-radius: 4px; border: 1px solid #ddd;">
                <?php foreach ($availableLanguages as $language): ?>
                    <option value="<?= e($language['lang']); ?>" <?= $_SESSION['lang'] === $language['lang'] ? 'selected' : '' ?>>
                        <?= e($language['UILanguage']); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </small>

        <script>
            function changeLanguage() {
                const lang = document.getElementById('langSelect').value;
                const currentPath = window.location.pathname;

                let newHost = '';
                if (lang === 'en') {
                    newHost = 'brunotutor.com';
                } else {
                    newHost = lang + '.brunotutor.com';
                }

                window.location.href = 'https://' + newHost + currentPath;
            }
        </script>
    </footer>
</body>

</html>