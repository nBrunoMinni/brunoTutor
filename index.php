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
            $_SESSION['lang'] = 'en'; // Fallback english
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
    die("Connection failed: " . $dbc->connect_error);
}
$dbc->set_charset("utf8mb4");

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

// Fetch subjects in current language
$subjectsQuery = $dbc->query("SELECT id, `$userLang` as subject_name FROM subjects ORDER BY `$userLang` ASC");
$subjects = [];
while ($subjectRow = $subjectsQuery->fetch_assoc()) {
    $subjects[$subjectRow['id']] = $subjectRow['subject_name'];
}

function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

$query = "SELECT * FROM bruno";
$rows = $dbc->query($query)->fetch_all(MYSQLI_ASSOC);
$keyedRows = [];
foreach ($rows as $row) {
    foreach ($row as $columnName => $value) {
        if ($columnName !== 'key') {
            $keyedRows[$columnName][$row['key']] = $value;
        }
    }
}
?>
<!doctype html>
<html>

<head>
    <title>BrunoTutor.com</title>
    <meta charset='utf-8' />
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/x-icon" href="home.ico">
    <link href="style.css" rel="stylesheet">
</head>

<body>
    <main class="main">
        <div class="container">
            <div class="row">
                <div class="col">
                    <div class="inline-content">
                        <a href="home.png" target="_blank">
                            <img src="home.png" title="home">
                        </a>
                        <div>
                            <h1 style="margin-top: 0;">BrunoTutor.com</h1>
                            <p style="margin-top: 0; margin-left: 2px;"><?= e($lang['tagline']); ?></p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col">
                    <h2><?= e($lang['about']); ?></h2>
                    <p>
                        <?= e($lang['connects']); ?><?= e($lang['foss']); ?> <a href="https://github.com/nBrunoMinni/brunoTutor" target="_blank"><?= e($lang['seeSource']); ?></a>. <?= e($lang['usesCalTo']); ?><?= e($lang['happyLearn']); ?>
                    </p>
                </div>
                <div class="col">
                    <h2><?= e($lang['create']); ?></h2>
                    <p>
                        <a href="regTutor.php"><?= e($lang['tutorsCan']); ?></a><?= e($lang['canEdit']); ?> <a href="editTutor.php"><?= e($lang['login']); ?></a>.
                    </p>
                </div>
            </div>
            <br>
            <div style="text-align: center; margin-bottom: 10px;">
                <h2><?= e($lang['tutors']); ?></h2>
            </div>
            <div class="buttons-container">
                <?php foreach ($keyedRows['name'] as $colName => $nameValue) :
                    if (in_array($colName, ['key', 'home', 'example'])) {
                        continue;
                    }

                    // Gather unique places from lesson1Place, lesson2Place, lesson3Place
                    $places = array_unique(array_filter([
                        $keyedRows['lesson1Place'][$colName] ?? '',
                        $keyedRows['lesson2Place'][$colName] ?? '',
                        $keyedRows['lesson3Place'][$colName] ?? ''
                    ]));

                    // Convert array to a comma-separated string
                    $placeValue = !empty($places) ? implode(", ", $places) : 'Online';

                    $tagsString = $keyedRows['tags'][$colName] ?? '';
                    $tagIds = array_filter(array_map('trim', explode(',', $tagsString)));

                    $badges = [];
                    foreach ($tagIds as $id) {
                        $displayName = $subjects[$id] ?? $id;
                        $badges[] = "<span class='badge'>" . htmlspecialchars($displayName) . "</span>";
                    }
                ?>
                    <a href="<?= urlencode($colName); ?>" class="chunky-button">
                        <div class="inline-content">
                            <img src="uploads/<?= e($colName); ?>.png" title="tutor pic">
                            <div>
                                <h2><?= e($nameValue); ?></h2>
                                <div class="button-content">
                                    <div class="info-row">
                                        <svg focusable="false" viewBox="0 0 24 24" width="20" height="20">
                                            <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                        </svg>
                                        <span title="<?= e($placeValue); ?>">
                                            <?= strlen($placeValue) > 16 ? e(substr($placeValue, 0, 16)) . '...' : e($placeValue); ?>
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div style="margin-top: 10px; justify-content: center; align-items: center; text-align: center;">
                            <div class="badge-wrapper">
                                <?= implode(" ", $badges); ?>
                            </div>
                        </div>
                    </a>
                <?php endforeach; ?>
            </div>
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