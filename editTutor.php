<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);
session_start();
session_regenerate_id(true);
require_once(__DIR__ . '/../../config/config.php');
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
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
    die("Database connection failed");
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


$langStmt = $dbc->query("SELECT lang, UILanguage FROM UILanguage ORDER BY lang ASC");
$availableLanguages = [];
while ($langRow = $langStmt->fetch_assoc()) {
    $availableLanguages[] = $langRow;
}

// Fetch subjects in current language
$subjectsQuery = $dbc->query("SELECT id, `$userLang` as subject_name FROM subjects ORDER BY `$userLang` ASC");
$subjects = [];
while ($subjectRow = $subjectsQuery->fetch_assoc()) {
    $subjects[] = $subjectRow;
}

// HTML escaping
function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

// Function to validate text content (server-side security)
function validateTextContent($text, $fieldName)
{
    $pattern = '/^[\p{L}\p{N}\s\-–—@,.;:!?¡¿*()\\/=+\'\r\n]+$/u';
    if (!empty($text) && !preg_match($pattern, $text)) {
        die("Invalid characters detected in {$fieldName}. Only letters (including accented), numbers, spaces, and basic punctuation are allowed.");
    }
}

// Smart URL validation 
function validateSmartURL($url, $fieldName)
{
    if (empty($url)) {
        return true;
    }
    $dangerousProtocols = '/^(javascript|data|vbscript|file|about):/i';
    if (preg_match($dangerousProtocols, trim($url))) {
        die("Dangerous URL protocol detected in {$fieldName}.");
    }
    if (strpos($url, ':') !== false) {
        $safeProtocols = '/^(https?|mailto):/i';
        if (!preg_match($safeProtocols, trim($url))) {
            die("Invalid URL protocol in {$fieldName}.");
        }
    }
    if (preg_match('/[\x00-\x1F\x7F]/', $url)) {
        die("URL in {$fieldName} contains invalid control characters.");
    }
    if (preg_match('/^https?:/', $url)) {
        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['scheme']) || !isset($parsed['host'])) {
            die("Malformed URL in {$fieldName}.");
        }
    }
    return true;
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: editTutor.php");
    exit;
}

if (isset($_POST['login'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $loginError = $lang['securityFail'];
    } else {
        $inputUser = $_POST['userLogin'] ?? '';
        $inputPass = $_POST['userPassword'] ?? '';

        $stmt = $dbc->prepare("SELECT failed_attempts, last_attempt_time FROM login_attempts WHERE userLogin = ? LIMIT 1");
        $stmt->bind_param('s', $inputUser);
        $stmt->execute();
        $result = $stmt->get_result();
        $lockoutInfo = $result->fetch_assoc();
        $stmt->close();

        $accountLocked = false;
        if ($lockoutInfo && $lockoutInfo['failed_attempts'] >= 3) {
            $lastAttemptTime = strtotime($lockoutInfo['last_attempt_time']);
            $timeElapsed = time() - $lastAttemptTime;

            if ($timeElapsed < 1800) {
                $accountLocked = true;
                $loginError = $lang['accountLocked'];
            } else {
                $stmt = $dbc->prepare("UPDATE login_attempts SET failed_attempts = 0 WHERE userLogin = ?");
                $stmt->bind_param('s', $inputUser);
                $stmt->execute();
                $stmt->close();
            }
        }

        if (!$accountLocked) {
            $stmt = $dbc->prepare("SELECT * FROM bruno WHERE userLogin = ? LIMIT 1");
            $stmt->bind_param('s', $inputUser);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result && $result->num_rows === 1) {
                $row = $result->fetch_assoc();
                if (password_verify($inputPass, $row['userHash'])) {
                    $stmt = $dbc->prepare("DELETE FROM login_attempts WHERE userLogin = ?");
                    $stmt->bind_param('s', $inputUser);
                    $stmt->execute();
                    $stmt->close();

                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    $_SESSION['tutorLogin'] = $row['userLogin'];
                    $_SESSION['tutorRow']   = $row;

                    header("Location: editTutor.php");
                    exit;
                } else {
                    updateLoginAttempts($dbc, $inputUser);
                    $loginError = $lang['invalidLogin'];
                }
            } else {
                updateLoginAttempts($dbc, $inputUser);
                $loginError = $lang['invalidLogin'];
            }
            $stmt->close();
        }
    }
}

function updateLoginAttempts($dbc, $userLogin)
{
    $currentTime = date('Y-m-d H:i:s');
    $stmt = $dbc->prepare("SELECT * FROM login_attempts WHERE userLogin = ? LIMIT 1");
    $stmt->bind_param('s', $userLogin);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $stmt = $dbc->prepare("UPDATE login_attempts SET failed_attempts = failed_attempts + 1, last_attempt_time = ? WHERE userLogin = ?");
        $stmt->bind_param('ss', $currentTime, $userLogin);
    } else {
        $stmt = $dbc->prepare("INSERT INTO login_attempts (userLogin, failed_attempts, last_attempt_time) VALUES (?, 1, ?)");
        $stmt->bind_param('ss', $userLogin, $currentTime);
    }
    $stmt->execute();
    $stmt->close();
}

// If not logged in, show login form:
if (!isset($_SESSION['tutorLogin'])):
?>
    <!doctype html>
    <html>

    <head>
        <title><?= e($lang['login']); ?> - BrunoTutor</title>
        <meta charset="utf-8" />
        <link href="style.css" rel="stylesheet">
        <link href="logStyle.css" rel="stylesheet">
        <link rel="icon" type="image/x-icon" href="home.ico">
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>

    <body>
        <main class="main">
            <div class="container" style="max-width: 400px; margin: 0 auto; text-align: center;">
                <h1><?= e($lang['login']); ?></h1>
                <?php if (!empty($loginError)): ?>
                    <p style="color: red; text-align:center;">
                        <strong><?= e($loginError) ?></strong>
                    </p>
                <?php endif; ?>
                <div class="form-container">
                    <form method="post" action="editTutor.php">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <label for="userLogin"><?= e($lang['username']); ?></label>
                            <input type="text" name="userLogin" id="userLogin" required>
                        </div>
                        <div>
                            <label for="userPassword"><?= e($lang['password']); ?></label>
                            <input type="password" name="userPassword" id="userPassword" style="margin-bottom: 5px;" required>
                            <div style="text-align: right; font-size: 0.8em; margin-top: 0;">
                                <a href="reset.php"><?= e($lang['forgot']); ?></a>
                            </div>
                        </div>
                        <button type="submit" name="login" class="login-btn"><?= e($lang['login']); ?></button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        <?= e($lang['dont']); ?> <a href="regTutor.php"><?= e($lang['register']); ?></a>
                    </p>
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
<?php
    exit;
endif;

if (isset($_POST['update']) && isset($_SESSION['tutorLogin'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }

    $name         = $_POST['name']         ?? '';
    $contact      = $_POST['contact']      ?? '';
    $URL          = $_POST['URL']          ?? '';
    $contact2     = $_POST['contact2']     ?? '';
    $URL2         = $_POST['URL2']         ?? '';
    $contact3     = $_POST['contact3']     ?? '';
    $URL3         = $_POST['URL3']         ?? '';
    $header       = $_POST['header']       ?? 'About Me';
    $about        = $_POST['about']        ?? '';
    $header2      = $_POST['header2']      ?? 'Lessons';
    $lessons      = $_POST['lessons']      ?? '';
    $video        = $_POST['video']        ?? '';
    $header3      = $_POST['header3']      ?? 'Booking';
    $booking      = $_POST['booking']      ?? '';
    $lesson1      = $_POST['lesson1']      ?? '';
    $lesson1Dur   = $_POST['lesson1Dur']   ?? '';
    $lesson1Cost  = $_POST['lesson1Cost']  ?? '';
    $lesson1Place = $_POST['lesson1Place'] ?? '';
    $lesson2      = $_POST['lesson2']      ?? '';
    $lesson2Dur   = $_POST['lesson2Dur']   ?? '';
    $lesson2Cost  = $_POST['lesson2Cost']  ?? '';
    $lesson2Place = $_POST['lesson2Place'] ?? '';
    $lesson3      = $_POST['lesson3']      ?? '';
    $lesson3Dur   = $_POST['lesson3Dur']   ?? '';
    $lesson3Cost  = $_POST['lesson3Cost']  ?? '';
    $lesson3Place = $_POST['lesson3Place'] ?? '';
    $calUser      = $_POST['calUser']      ?? '';
    $tags         = isset($_POST['tags']) ? $_POST['tags'] : '';

    // Length validation
    if (strlen($URL) > 99) die("URL 1 exceeds maximum length of 99 characters");
    if (strlen($URL2) > 99) die("URL 2 exceeds maximum length of 99 characters");
    if (strlen($URL3) > 99) die("URL 3 exceeds maximum length of 99 characters");
    if (strlen($video) > 99) die("Video URL exceeds maximum length of 99 characters");

    // Validate platform
    $allowedPlatforms = ['youtube', 'facebook', 'line', 'instagram', 'whatsApp', 'linktree', 'email'];
    if ($contact && !in_array($contact, $allowedPlatforms)) {
        die("Invalid platform selected for Link 1");
    }
    if ($contact2 && !in_array($contact2, $allowedPlatforms)) {
        die("Invalid platform selected for Link 2");
    }
    if ($contact3 && !in_array($contact3, $allowedPlatforms)) {
        die("Invalid platform selected for Link 3");
    }

    $platformUrls = [
        'youtube' => ['https://www.youtube.com/', 'https://youtube.com/'],
        'facebook' => ['https://facebook.com/', 'https://www.facebook.com/'],
        'line' => ['https://line.me/ti/p/'],
        'instagram' => ['https://instagram.com/', 'https://www.instagram.com/'],
        'whatsApp' => ['https://wa.me/', 'wa.me/'],
        'linktree' => ['https://linktr.ee/', 'linktr.ee/'],
        'email' => ['mailto:']
    ];

    function validateAndProcessURL($platform, $url, $platformUrls)
    {
        if (empty($platform) || empty($url)) {
            return '';
        }
        validateSmartURL($url, "contact URL");
        if (preg_match('/^https?:\/\/|^mailto:/', $url)) {
            $validUrls = $platformUrls[$platform] ?? [];
            $isValid = false;
            foreach ($validUrls as $validUrl) {
                if (strpos($url, $validUrl) === 0) {
                    $isValid = true;
                    break;
                }
            }
            if (!$isValid) {
                die("Invalid URL for selected platform: $platform");
            }
            foreach ($validUrls as $validUrl) {
                if (strpos($url, $validUrl) === 0) {
                    $username = substr($url, strlen($validUrl));
                    return preg_replace('/[^a-zA-Z0-9\-_.@]/', '', $username);
                }
            }
        } else {
            return preg_replace('/[^a-zA-Z0-9\-_.@]/', '', $url);
        }
        return '';
    }

    $URL = validateAndProcessURL($contact, $URL, $platformUrls);
    $URL2 = validateAndProcessURL($contact2, $URL2, $platformUrls);
    $URL3 = validateAndProcessURL($contact3, $URL3, $platformUrls);

    // Validate YouTube video
    if (!empty($video)) {
        validateSmartURL($video, "YouTube video");
        $youtubePatterns = [
            '/^https:\/\/(www\.)?youtube\.com\/watch\?v=[a-zA-Z0-9_-]+/',
            '/^https:\/\/youtu\.be\/[a-zA-Z0-9_-]+/'
        ];
        $isValidYouTube = false;
        foreach ($youtubePatterns as $pattern) {
            if (preg_match($pattern, $video)) {
                $isValidYouTube = true;
                break;
            }
        }
        if (!$isValidYouTube) {
            die("Invalid YouTube URL.");
        }
    }

    // Validate required fields
    if ($contact && empty($URL)) {
        die("Username/ID required for Link 1");
    }
    if ($contact2 && empty($URL2)) {
        die("Username/ID required for Link 2");
    }
    if ($contact3 && empty($URL3)) {
        die("Username/ID required for Link 3");
    }

    // Validate text content
    validateTextContent($name, 'Name');
    validateTextContent($header, 'Header 1');
    validateTextContent($about, 'About');
    validateTextContent($header2, 'Header 2');
    validateTextContent($lessons, 'Lessons');
    validateTextContent($header3, 'Header 3');
    validateTextContent($booking, 'Booking');
    validateTextContent($lesson1, 'Lesson 1 Title');
    validateTextContent($lesson1Dur, 'Lesson 1 Duration');
    validateTextContent($lesson1Cost, 'Lesson 1 Cost');
    validateTextContent($lesson1Place, 'Lesson 1 Place');
    validateTextContent($lesson2, 'Lesson 2 Title');
    validateTextContent($lesson2Dur, 'Lesson 2 Duration');
    validateTextContent($lesson2Cost, 'Lesson 2 Cost');
    validateTextContent($lesson2Place, 'Lesson 2 Place');
    validateTextContent($lesson3, 'Lesson 3 Title');
    validateTextContent($lesson3Dur, 'Lesson 3 Duration');
    validateTextContent($lesson3Cost, 'Lesson 3 Cost');
    validateTextContent($lesson3Place, 'Lesson 3 Place');
    validateTextContent($calUser, 'Cal.com Username');
    validateTextContent($tags, 'Tags');

    // Image validation
    if (!empty($_FILES['profileImage']['name'])) {
        $uploadDir = "uploads/";
        $uploadError = null;

        if (!is_dir($uploadDir) || !is_writable($uploadDir)) {
            $uploadError = "Upload directory error!";
        } elseif (empty($_FILES['profileImage']['tmp_name']) || !file_exists($_FILES['profileImage']['tmp_name'])) {
            $uploadError = "No file uploaded or upload failed!";
        } else {
            $fileKey = $_SESSION['tutorLogin'] . ".png";
            $targetFile = $uploadDir . $fileKey;

            $allowedTypes = ['image/png'];
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $fileType = $finfo->file($_FILES['profileImage']['tmp_name']);

            if (!in_array($fileType, $allowedTypes)) {
                $uploadError = "File is not a valid PNG image!";
            } elseif ($_FILES['profileImage']['size'] > 2 * 1024 * 1024) {
                $uploadError = "File is too large! Max 2MB allowed.";
            } else {
                list($width, $height) = getimagesize($_FILES['profileImage']['tmp_name']);
                if ($width > 4000 || $height > 4000) {
                    $uploadError = "Image dimensions too large!";
                } else {
                    $image = @imagecreatefrompng($_FILES['profileImage']['tmp_name']);
                    if (!$image) {
                        $uploadError = "Invalid image content!";
                    } else {
                        $newImage = imagecreatetruecolor($width, $height);
                        imagecopy($newImage, $image, 0, 0, 0, 0, $width, $height);
                        if (!imagepng($newImage, $targetFile)) {
                            $uploadError = "Error saving image.";
                        }
                        imagedestroy($image);
                        imagedestroy($newImage);
                    }
                }
            }
        }
        if ($uploadError) {
            echo "<script>alert('" . htmlspecialchars($uploadError, ENT_QUOTES, 'UTF-8') . "');</script>";
        }
    }

    $stmt = $dbc->prepare("
        UPDATE bruno 
        SET 
            name = ?, 
            contact = ?, 
            URL = ?, 
            contact2 = ?, 
            URL2 = ?,
            contact3 = ?,
            URL3 = ?,
            header = ?,
            about = ?,
            header2 = ?,
            lessons = ?,
            video = ?,
            header3 = ?,
            booking = ?, 
            lesson1 = ?, 
            lesson1Duration = ?, 
            lesson1Cost = ?, 
            lesson1Place = ?, 
            lesson2 = ?, 
            lesson2Duration = ?, 
            lesson2Cost = ?, 
            lesson2Place = ?, 
            lesson3 = ?, 
            lesson3Duration = ?, 
            lesson3Cost = ?, 
            lesson3Place = ?, 
            calUser = ?, 
            tags = ? 
        WHERE userLogin = ?
        LIMIT 1
    ");

    if (!$stmt) {
        die("Prepare failed.");
    }

    $stmt->bind_param(
        'sssssssssssssssssssssssssssss',
        $name,
        $contact,
        $URL,
        $contact2,
        $URL2,
        $contact3,
        $URL3,
        $header,
        $about,
        $header2,
        $lessons,
        $video,
        $header3,
        $booking,
        $lesson1,
        $lesson1Dur,
        $lesson1Cost,
        $lesson1Place,
        $lesson2,
        $lesson2Dur,
        $lesson2Cost,
        $lesson2Place,
        $lesson3,
        $lesson3Dur,
        $lesson3Cost,
        $lesson3Place,
        $calUser,
        $tags,
        $_SESSION['tutorLogin']
    );

    if ($stmt->execute()) {
        $updateMessage = $lang['changesSaved'];
        $stmt2 = $dbc->prepare("SELECT * FROM bruno WHERE userLogin = ? LIMIT 1");
        $stmt2->bind_param('s', $_SESSION['tutorLogin']);
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        if ($res2 && $res2->num_rows === 1) {
            $_SESSION['tutorRow'] = $res2->fetch_assoc();
        }
        $stmt2->close();
    } else {
        $updateMessage = $lang['failed'];
    }
    $stmt->close();
}

$row = $_SESSION['tutorRow'] ?? null;
if (!$row) {
    $stmt = $dbc->prepare("SELECT * FROM bruno WHERE userLogin = ? LIMIT 1");
    $stmt->bind_param('s', $_SESSION['tutorLogin']);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result && $result->num_rows === 1) {
        $row = $result->fetch_assoc();
        $_SESSION['tutorRow'] = $row;
    }
    $stmt->close();
}

$name         = $row['name']             ?? '';
$contact      = $row['contact']          ?? '';
$URL          = $row['URL']              ?? '';
$contact2     = $row['contact2']         ?? '';
$URL2         = $row['URL2']             ?? '';
$contact3     = $row['contact3']         ?? '';
$URL3         = $row['URL3']             ?? '';
$header       = $row['header']           ?? 'About Me';
$about        = $row['about']            ?? '';
$header2      = $row['header2']          ?? 'Lessons';
$lessons      = $row['lessons']          ?? '';
$video        = $row['video']            ?? '';
$header3      = $row['header3']          ?? 'Booking';
$booking      = $row['booking']          ?? '';
$lesson1      = $row['lesson1']          ?? '';
$lesson1Dur   = $row['lesson1Duration']  ?? '';
$lesson1Cost  = $row['lesson1Cost']      ?? '';
$lesson1Place = $row['lesson1Place']     ?? '';
$lesson2      = $row['lesson2']          ?? '';
$lesson2Dur   = $row['lesson2Duration']  ?? '';
$lesson2Cost  = $row['lesson2Cost']      ?? '';
$lesson2Place = $row['lesson2Place']     ?? '';
$lesson3      = $row['lesson3']          ?? '';
$lesson3Dur   = $row['lesson3Duration']  ?? '';
$lesson3Cost  = $row['lesson3Cost']      ?? '';
$lesson3Place = $row['lesson3Place']     ?? '';
$calUser      = $row['calUser']          ?? '';
$tags         = $row['tags']             ?? '';
?>
<!doctype html>
<html>

<head>
    <title>BrunoTutor.com - <?= e($name ?: $_SESSION['tutorLogin']) ?></title>
    <meta charset="utf-8" />
    <link href="style.css" rel="stylesheet">
    <link rel="icon" type="image/x-icon" href="home.ico">
    <link href="userStyle.css" rel="stylesheet">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>

<body>
    <main class="main">
        <div class="container">
            <form method="post" action="editTutor.php" enctype="multipart/form-data">
                <input type="hidden" name="update" value="1">
                <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">

                <!-- Profile Image -->
                <div class="row">
                    <div class="col">
                        <label for="profileImage"><?= e($lang['photo']); ?></label><br>
                        <input type="file" name="profileImage" id="profileImage" accept="image/png">
                    </div>
                </div>
                <br>

                <div class="row">
                    <div class="col">
                        <div class="inline-content">
                            <?php
                            $uploadedImage = "uploads/" . ($_SESSION['tutorLogin'] ?? 'default') . ".png";
                            if (!file_exists($uploadedImage)) {
                                $uploadedImage = "default.png";
                            }
                            ?>
                            <img src="<?= e($uploadedImage) ?>" alt="Profile Image" style="width: 150px; height: auto; border-radius: 5px;">
                            <div>
                                <input type="text" id="name" name="name" placeholder="<?= e($lang['name']); ?>" style="font-size: 2rem; margin-bottom: 0;" value="<?= e($name) ?>" required maxlength="30"><br>

                                <div style="margin-top: 10px; display: flex; gap: 15px; flex-wrap: wrap;">
                                    <!-- Contact Link 1 (Required) -->
                                    <div style="flex: 1; min-width: 250px;">
                                        <select id="contact" name="contact" required style="width: 100%; margin-bottom: 5px;">
                                            <option value=""><?= e($lang['link']); ?>:</option>
                                            <option value="youtube" <?= $contact === 'youtube' ? 'selected' : '' ?>>YouTube</option>
                                            <option value="facebook" <?= $contact === 'facebook' ? 'selected' : '' ?>>Facebook</option>
                                            <option value="line" <?= $contact === 'line' ? 'selected' : '' ?>>Line</option>
                                            <option value="instagram" <?= $contact === 'instagram' ? 'selected' : '' ?>>Instagram</option>
                                            <option value="whatsApp" <?= $contact === 'whatsApp' ? 'selected' : '' ?>>WhatsApp</option>
                                            <option value="linktree" <?= $contact === 'linktree' ? 'selected' : '' ?>>Linktree</option>
                                            <option value="email" <?= $contact === 'email' ? 'selected' : '' ?>>Email</option>
                                        </select>
                                        <input type="text" id="URL" name="URL" placeholder="URL or username/ID" maxlength="99" value="<?= e($URL) ?>" required style="width: 100%;">
                                        <small id="url1Error" style="color: red; display: none;"><?= e($lang['URLError']); ?></small>
                                    </div>

                                    <!-- Contact Link 2 (Optional) -->
                                    <div style="flex: 1; min-width: 250px;">
                                        <select id="contact2" name="contact2" style="width: 100%; margin-bottom: 5px;">
                                            <option value=""><?= e($lang['link']); ?> 2 <?= e($lang['optional']); ?>:</option>
                                            <option value="youtube" <?= $contact2 === 'youtube' ? 'selected' : '' ?>>YouTube</option>
                                            <option value="facebook" <?= $contact2 === 'facebook' ? 'selected' : '' ?>>Facebook</option>
                                            <option value="line" <?= $contact2 === 'line' ? 'selected' : '' ?>>Line</option>
                                            <option value="instagram" <?= $contact2 === 'instagram' ? 'selected' : '' ?>>Instagram</option>
                                            <option value="whatsApp" <?= $contact2 === 'whatsApp' ? 'selected' : '' ?>>WhatsApp</option>
                                            <option value="linktree" <?= $contact2 === 'linktree' ? 'selected' : '' ?>>Linktree</option>
                                            <option value="email" <?= $contact2 === 'email' ? 'selected' : '' ?>>Email</option>
                                        </select>
                                        <input type="text" id="URL2" name="URL2" placeholder="URL or username/ID" maxlength="99" value="<?= e($URL2) ?>" style="width: 100%;">
                                        <small id="url2Error" style="color: red; display: none;"><?= e($lang['URLError']); ?></small>
                                    </div>

                                    <!-- Contact Link 3 (Optional) -->
                                    <div style="flex: 1; min-width: 250px;">
                                        <select id="contact3" name="contact3" style="width: 100%; margin-bottom: 5px;">
                                            <option value=""><?= e($lang['link']); ?> 3 <?= e($lang['optional']); ?>:</option>
                                            <option value="youtube" <?= $contact3 === 'youtube' ? 'selected' : '' ?>>YouTube</option>
                                            <option value="facebook" <?= $contact3 === 'facebook' ? 'selected' : '' ?>>Facebook</option>
                                            <option value="line" <?= $contact3 === 'line' ? 'selected' : '' ?>>Line</option>
                                            <option value="instagram" <?= $contact3 === 'instagram' ? 'selected' : '' ?>>Instagram</option>
                                            <option value="whatsApp" <?= $contact3 === 'whatsApp' ? 'selected' : '' ?>>WhatsApp</option>
                                            <option value="linktree" <?= $contact3 === 'linktree' ? 'selected' : '' ?>>Linktree</option>
                                            <option value="email" <?= $contact3 === 'email' ? 'selected' : '' ?>>Email</option>
                                        </select>
                                        <input type="text" id="URL3" name="URL3" placeholder="URL or username/ID" maxlength="99" value="<?= e($URL3) ?>" style="width: 100%;">
                                        <small id="url3Error" style="color: red; display: none;"><?= e($lang['URLError']); ?></small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <br>

                <div class="row" style="margin-top: 1.5rem;">
                    <div class="col">
                        <input type="text" id="header" name="header" placeholder="<?= e($lang['header']); ?> 1" maxlength="30" value="<?= e($header) ?>" required style="width: 100%; font-size: 1.5rem; font-weight: bold; margin-bottom: 10px;">
                        <textarea style="width: 100%; height: 70%;" id="about" name="about" placeholder="<?= e($lang['content']); ?>..." rows="5" maxlength="1200" required><?= e($about) ?></textarea>
                    </div>
                    <div class="col">
                        <input type="text" id="header2" name="header2" placeholder="<?= e($lang['header']); ?> 2" maxlength="30" value="<?= e($header2) ?>" style="width: 100%; font-size: 1.5rem; font-weight: bold; margin-bottom: 10px;">
                        <textarea style="width: 100%;" id="lessons" name="lessons" placeholder="<?= e($lang['content']); ?>..." rows="5" maxlength="1200"><?= e($lessons) ?></textarea>
                        <br>

                        <label for="video"><strong><?= e($lang['video']); ?> <?= e($lang['optional']); ?>:</strong></label><br>
                        <input type="text" id="video" name="video" placeholder="https://www.youtube.com/watch?v=VIDEO_ID" style="width: 80%;" maxlength="99" value="<?= e($video) ?>">
                        <br><small id="videoError" style="color: red; display: none;"><?= e($lang['URLError']); ?></small>
                    </div>
                </div>
                <br>

                <div class="row" style="margin-top: 1.5rem;">
                    <div class="col" style="text-align: center;">
                        <input type="text" id="header3" name="header3" placeholder="<?= e($lang['header']); ?> 3" maxlength="30" value="<?= e($header3) ?>" style="text-align: center; font-size: 1.5rem; font-weight: bold; margin-bottom: 10px; width: 50%;">
                        <textarea id="booking" name="booking" rows="3" style="width: 80%;" placeholder="<?= e($lang['content']); ?>..." maxlength="1200"><?= e($booking) ?></textarea>
                    </div>
                </div>
                <br>

                <div class="buttons-container">
                    <div class="chunky-button">
                        <div class="button-content">
                            <div class="input-row">
                                <input type="text" id="lesson1" name="lesson1" placeholder="<?= e($lang['lessonTitle']); ?> 1" style="margin: 0; font-size: 18px; color: #333;" value="<?= e($lesson1) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <input type="text" id="lesson1Dur" name="lesson1Dur" placeholder="<?= e($lang['duration']); ?>" value="<?= e($lesson1Dur) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <input type="text" id="lesson1Cost" name="lesson1Cost" placeholder="<?= e($lang['cost']); ?>" value="<?= e($lesson1Cost) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <input type="text" id="lesson1Place" name="lesson1Place" placeholder="<?= e($lang['place']); ?>" value="<?= e($lesson1Place) ?>" maxlength="20">
                            </div>
                        </div>
                    </div>

                    <div class="chunky-button">
                        <div class="button-content">
                            <div class="input-row">
                                <input type="text" id="lesson2" name="lesson2" placeholder="<?= e($lang['lessonTitle']); ?> 2 <?= e($lang['optional']); ?>" style="margin: 0; font-size: 18px; color: #333;" value="<?= e($lesson2) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <input type="text" id="lesson2Dur" name="lesson2Dur" placeholder="<?= e($lang['duration']); ?>" value="<?= e($lesson2Dur) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <input type="text" id="lesson2Cost" name="lesson2Cost" placeholder="<?= e($lang['cost']); ?>" value="<?= e($lesson2Cost) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <input type="text" id="lesson2Place" name="lesson2Place" placeholder="<?= e($lang['place']); ?>" value="<?= e($lesson2Place) ?>" maxlength="20">
                            </div>
                        </div>
                    </div>

                    <div class="chunky-button">
                        <div class="button-content">
                            <div class="input-row">
                                <input type="text" id="lesson3" name="lesson3" placeholder="<?= e($lang['lessonTitle']); ?> 3 <?= e($lang['optional']); ?>" style="margin: 0; font-size: 18px; color: #333;" value="<?= e($lesson3) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <input type="text" id="lesson3Dur" name="lesson3Dur" placeholder="<?= e($lang['duration']); ?>" value="<?= e($lesson3Dur) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <input type="text" id="lesson3Cost" name="lesson3Cost" placeholder="<?= e($lang['cost']); ?>" value="<?= e($lesson3Cost) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <input type="text" id="lesson3Place" name="lesson3Place" placeholder="<?= e($lang['place']); ?>" value="<?= e($lesson3Place) ?>" maxlength="20">
                            </div>
                        </div>
                    </div>
                </div>
                <br>
                <hr>

                <div class="buttons-container" style="margin-top: 1.5rem; margin-bottom: 1.5; padding-top: 0; gap: 10px;">
                    <label for="calUser"><strong>Cal.com:</strong></label>
                    <input type="text" id="calUser" name="calUser" placeholder="Cal.com" value="<?= e($calUser) ?>">
                </div>
                <div class="buttons-container" style="margin-top: 0; margin-bottom: 1.5rem; padding-top: 0;">
                    <small><a href="help.php" target="_blank"><?= e($lang['guide']); ?></a></small>
                </div>

                <!-- Tags -->
                <div class="buttons-container" style="margin-top: 1.5rem; margin-bottom: 1.5rem; padding-top: 0; gap: 10px;">
                    <div class="custom-select" id="customSelect">
                        <div class="select-box" id="selectBox"><?= e($lang['select']); ?></div>
                        <div class="checkbox-dropdown">
                            <?php foreach ($subjects as $subject): ?>
                                <label>
                                    <input type="checkbox" value="<?= htmlspecialchars($subject['id']) ?>">
                                    <?= htmlspecialchars($subject['subject_name']) ?>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
                <input type="hidden" name="tags" id="tagsHidden">

                <div class="buttons-container" style="display: flex; gap: 10px;">
                    <label>
                        <input type="checkbox" id="tosCheckbox" required>
                        <?= e($lang['confirm']); ?> <a href="tos.php" target="_blank"><?= e($lang['terms']); ?></a>
                    </label>
                </div>

                <div class="buttons-container" style="display: flex; gap: 10px;">
                    <button type="submit" class="save"><?= e($lang['submit']); ?></button>
                </div>

                <div class="buttons-container" style="display: flex; gap: 10px;">
                    <a href="editTutor.php?logout=1" style="color: #FF7276;"><?= e($lang['logout']); ?></a>
                </div>

                <?php if (!empty($updateMessage)): ?>
                    <script>
                        document.addEventListener("DOMContentLoaded", function() {
                            let alertBox = document.createElement("div");
                            alertBox.textContent = "<?= e($updateMessage) ?>";
                            alertBox.style.cssText = `
                                position: fixed;
                                top: 20px;
                                left: 50%;
                                transform: translateX(-50%);
                                background: #ADDFB3;
                                padding: 10px 20px;
                                border-radius: 5px;
                                font-size: 16px;
                                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                                opacity: 1;
                                transition: opacity 1s ease-in-out;
                                z-index: 1000;
                            `;
                            document.body.appendChild(alertBox);
                            setTimeout(() => {
                                alertBox.style.opacity = "0";
                                setTimeout(() => alertBox.remove(), 1000);
                            }, 3000);
                        });
                    </script>
                <?php endif; ?>
            </form>
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

    <script>
        // Load language strings from PHP
        const lang = {
            URLError: <?= json_encode($lang['URLError']); ?>,
            pleaseFix: <?= json_encode($lang['pleaseFix']); ?>,
            imgError: <?= json_encode($lang['imgError']); ?>,
            selectTags: <?= json_encode($lang['select']); ?>,
            error: <?= json_encode($lang['error']); ?>,
            only: <?= json_encode($lang['only']); ?>
        };

        document.addEventListener("DOMContentLoaded", function() {
            const allowedPattern = /^[\p{L}\p{N}\s\-–—@,.;:!?¡¿*()\\/=+'\n\r]+$/u;

            function validateTextInput(input) {
                const value = input.value;

                if (value && !allowedPattern.test(value)) {
                    // Find invalid character
                    const invalidChar = value.split('').find(char => !allowedPattern.test(char));
                    alert(`${lang.error} "${invalidChar}" ${lang.only}`);
                    // Remove invalid characters
                    input.value = value.replace(/[^\p{L}\p{N}\s\-–—@,.;:!?¡¿*()\\/=+'\n\r]/gu, '');
                    return false;
                }
                return true;
            }

            const textInputs = document.querySelectorAll('input[type="text"]:not(#URL):not(#URL2):not(#URL3):not(#video), textarea');
            textInputs.forEach(input => {
                input.addEventListener('paste', function(e) {
                    setTimeout(() => validateTextInput(this), 0);
                });
                input.addEventListener('input', function() {
                    validateTextInput(this);
                });
                input.addEventListener('blur', function() {
                    validateTextInput(this);
                });
            });

            // Tags 
            const selectBox = document.getElementById("selectBox");
            const customSelect = document.getElementById("customSelect");
            const checkboxes = document.querySelectorAll(".checkbox-dropdown input[type='checkbox']");
            const hiddenInput = document.getElementById("tagsHidden");

            if (selectBox) {
                const defaultText = lang.selectTags;

                selectBox.addEventListener("click", function(event) {
                    event.stopPropagation();
                    customSelect.classList.toggle("active");
                });

                document.addEventListener("click", function(event) {
                    if (!customSelect.contains(event.target)) {
                        customSelect.classList.remove("active");
                    }
                });

                checkboxes.forEach(checkbox => {
                    checkbox.addEventListener("change", function() {
                        let selected = Array.from(checkboxes)
                            .filter(cb => cb.checked)
                            .map(cb => cb.value);

                        if (selected.length > 3) {
                            alert(`${lang.select} 3/3`);
                            this.checked = false;
                            return;
                        }
                        selectBox.innerText = selected.length ? selected.join(", ") : defaultText;
                        hiddenInput.value = selected.join(", ");
                    });
                });

                let preselectedTags = "<?= e($tags) ?>".split(",").map(t => t.trim()).filter(tag => tag !== "");
                checkboxes.forEach(checkbox => {
                    if (preselectedTags.includes(checkbox.value)) {
                        checkbox.checked = true;
                    }
                });

                let tagNames = [];
                preselectedTags.forEach(tagId => {
                    checkboxes.forEach(cb => {
                        if (cb.value === tagId) {
                            tagNames.push(cb.parentElement.textContent.trim());
                        }
                    });
                });
                selectBox.innerText = tagNames.length > 0 ? tagNames.join(", ") : defaultText;
                hiddenInput.value = preselectedTags.join(",");
            }

            const contact1Select = document.getElementById("contact");
            const contact2Select = document.getElementById("contact2");
            const contact3Select = document.getElementById("contact3");
            const url1Input = document.getElementById("URL");
            const url2Input = document.getElementById("URL2");
            const url3Input = document.getElementById("URL3");
            const url1Error = document.getElementById("url1Error");
            const url2Error = document.getElementById("url2Error");
            const url3Error = document.getElementById("url3Error");
            const videoInput = document.getElementById("video");
            const videoError = document.getElementById("videoError");

            const platformUrls = {
                'youtube': ['https://www.youtube.com/', 'https://youtube.com/', 'youtube.com/'],
                'facebook': ['https://facebook.com/', 'https://www.facebook.com/', 'facebook.com/'],
                'line': ['https://line.me/ti/p/', 'line.me/ti/p/'],
                'instagram': ['https://instagram.com/', 'https://www.instagram.com/', 'instagram.com/'],
                'whatsApp': ['https://wa.me/', 'wa.me/'],
                'linktree': ['https://linktr.ee/', 'linktr.ee/'],
                'email': ['mailto:']
            };

            function validateSmartURL(url, errorElement) {
                if (!url) return true;
                const dangerousProtocols = /^(javascript|data|vbscript|file|about):/i;
                if (dangerousProtocols.test(url.trim())) {
                    errorElement.textContent = lang.URLError;
                    errorElement.style.display = 'block';
                    return false;
                }
                if (url.includes(':')) {
                    const safeProtocols = /^(https?|mailto):/i;
                    if (!safeProtocols.test(url.trim())) {
                        errorElement.textContent = lang.URLError;
                        errorElement.style.display = 'block';
                        return false;
                    }
                }
                if (/[\x00-\x1F\x7F]/.test(url)) {
                    errorElement.textContent = lang.URLError;
                    errorElement.style.display = 'block';
                    return false;
                }
                return true;
            }

            function validateURL(platform, url, errorElement) {
                if (!platform || !url) {
                    errorElement.style.display = 'none';
                    return true;
                }
                if (!validateSmartURL(url, errorElement)) return false;
                if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('mailto:')) {
                    const validUrls = platformUrls[platform];
                    const isValid = validUrls.some(validUrl => url.startsWith(validUrl));
                    if (!isValid) {
                        errorElement.textContent = lang.URLError;
                        errorElement.style.display = 'block';
                        return false;
                    }
                } else {
                    if (!/^[a-zA-Z0-9\-_.@]+$/.test(url)) {
                        errorElement.textContent = lang.URLError;
                        errorElement.style.display = 'block';
                        return false;
                    }
                }
                errorElement.style.display = 'none';
                return true;
            }

            function validateYouTubeVideo(url, errorElement) {
                if (!url) {
                    errorElement.style.display = 'none';
                    return true;
                }
                if (!validateSmartURL(url, errorElement)) return false;
                const youtubePatterns = [
                    /^https:\/\/(www\.)?youtube\.com\/watch\?v=([a-zA-Z0-9_-]+)/,
                    /^https:\/\/youtu\.be\/([a-zA-Z0-9_-]+)/,
                    /^https:\/\/(www\.)?youtube\.com\/embed\/([a-zA-Z0-9_-]+)/
                ];
                let isValid = false;
                for (let pattern of youtubePatterns) {
                    if (pattern.test(url)) {
                        isValid = true;
                        break;
                    }
                }
                if (!isValid) {
                    errorElement.textContent = lang.URLError;
                    errorElement.style.display = 'block';
                    return false;
                }
                errorElement.style.display = 'none';
                return true;
            }

            url1Input.addEventListener('input', function() {
                validateURL(contact1Select.value, this.value, url1Error);
            });
            url2Input.addEventListener('input', function() {
                validateURL(contact2Select.value, this.value, url2Error);
            });
            url3Input.addEventListener('input', function() {
                validateURL(contact3Select.value, this.value, url3Error);
            });
            videoInput.addEventListener('input', function() {
                validateYouTubeVideo(this.value, videoError);
            });
            contact1Select.addEventListener('change', function() {
                validateURL(this.value, url1Input.value, url1Error);
            });
            contact2Select.addEventListener('change', function() {
                validateURL(this.value, url2Input.value, url2Error);
            });
            contact3Select.addEventListener('change', function() {
                validateURL(this.value, url3Input.value, url3Error);
            });

            document.querySelector('form').addEventListener('submit', function(e) {
                const valid1 = validateURL(contact1Select.value, url1Input.value, url1Error);
                const valid2 = validateURL(contact2Select.value, url2Input.value, url2Error);
                const valid3 = validateURL(contact3Select.value, url3Input.value, url3Error);
                const validVideo = validateYouTubeVideo(videoInput.value, videoError);
                if (!valid1 || !valid2 || !valid3 || !validVideo) {
                    e.preventDefault();
                    alert(lang.pleaseFix);
                    return false;
                }
            });

            // Image validation
            const profileImageInput = document.getElementById("profileImage");
            if (profileImageInput) {
                profileImageInput.addEventListener('change', function(e) {
                    const file = e.target.files[0];
                    if (!file) return;
                    if (file.type !== 'image/png') {
                        alert(lang.imgError);
                        this.value = '';
                        return;
                    }
                    const maxSize = 2 * 1024 * 1024;
                    if (file.size > maxSize) {
                        alert(lang.imgError);
                        this.value = '';
                        return;
                    }
                    const img = new Image();
                    const objectUrl = URL.createObjectURL(file);
                    img.onload = function() {
                        URL.revokeObjectURL(objectUrl);
                        if (img.width > 4000 || img.height > 4000) {
                            alert(lang.imgError);
                            profileImageInput.value = '';
                            return;
                        }
                    };
                    img.onerror = function() {
                        URL.revokeObjectURL(objectUrl);
                        alert(lang.imgError);
                        profileImageInput.value = '';
                    };
                    img.src = objectUrl;
                });
            }
        });
    </script>
</body>

</html>