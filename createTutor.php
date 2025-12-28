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


// Redirect if user hasn't verified their email
if (!isset($_SESSION['email_verified']) || $_SESSION['email_verified'] !== true) {
    header("Location: regTutor.php");
    exit;
}

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

    // Check for danger
    $dangerousProtocols = '/^(javascript|data|vbscript|file|about):/i';
    if (preg_match($dangerousProtocols, trim($url))) {
        die("Dangerous URL protocol detected in {$fieldName}. Only http://, https://, and mailto: are allowed.");
    }

    // For full URLs, validate they start with safe protocols
    if (strpos($url, ':') !== false) {
        $safeProtocols = '/^(https?|mailto):/i';
        if (!preg_match($safeProtocols, trim($url))) {
            die("Invalid URL protocol in {$fieldName}. Only http://, https://, and mailto: are allowed.");
        }
    }

    // Check for null bytes and control characters
    if (preg_match('/[\x00-\x1F\x7F]/', $url)) {
        die("URL in {$fieldName} contains invalid control characters.");
    }

    // Parse the URL to validate structure (for full URLs)
    if (preg_match('/^https?:/', $url)) {
        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['scheme']) || !isset($parsed['host'])) {
            die("Malformed URL in {$fieldName}.");
        }
    }

    return true;
}

function sendUserConfirmationEmail($email, $lang)
{
    $to = $email;
    $subject = "BrunoTutor - " . $lang['create'];
    $message = "
    <html>
    <head>
        <title>" . htmlspecialchars($lang['create'], ENT_QUOTES, 'UTF-8') . "</title>
    </head>
    <body>
        <p>" . htmlspecialchars($lang['thank'], ENT_QUOTES, 'UTF-8') . "</p>
        <p>" . htmlspecialchars($lang['underReview'], ENT_QUOTES, 'UTF-8') . "</p>
        <p>" . htmlspecialchars($lang['timeline'], ENT_QUOTES, 'UTF-8') . "</p>
    </body>
    </html>
    ";
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= 'From: no-reply@brunotutor.com' . "\r\n";
    return mail($to, $subject, $message, $headers);
}

function sendAdminNotificationEmail($userLogin, $email)
{
    $to = "nbrunominni@gmail.com";
    $subject = "New Tutor Profile Submission";
    $message = "
    <html>
    <head>
        <title>New Tutor Profile</title>
    </head>
    <body>
        <p>A new tutor profile has been submitted and requires review.</p>
        <p><strong>Username:</strong> " . htmlspecialchars($userLogin, ENT_QUOTES, 'UTF-8') . "</p>
        <p><strong>Email:</strong> " . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . "</p>
        <p><strong>Review:</strong> <a href='https://brunotutor.com/sub.php?name=" . urlencode($userLogin) . "'>https://brunotutor.com/sub.php?name=" . urlencode($userLogin) . "</a></p>
    </body>
    </html>
    ";

    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= 'From: no-reply@brunotutor.com' . "\r\n";
    return mail($to, $subject, $message, $headers);
}

// Variable to track if profile submission was successful
$submission_success = false;


// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed. Please try again.");
    }

    $userLogin = $_SESSION['reg_userLogin'] ?? '';
    $userHash = $_SESSION['reg_userHash'] ?? '';
    $email = $_SESSION['reg_email'] ?? '';

    // Form data
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


    if (strlen($URL) > 99) die("URL 1 exceeds maximum length of 99 characters");
    if (strlen($URL2) > 99) die("URL 2 exceeds maximum length of 99 characters");
    if (strlen($URL3) > 99) die("URL 3 exceeds maximum length of 99 characters");
    if (strlen($video) > 99) die("Video URL exceeds maximum length of 99 characters");

    // Validate platform is from allowed list
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

    // Define allowed URL patterns for each platform
    $platformUrls = [
        'youtube' => ['https://www.youtube.com/', 'https://youtube.com/'],
        'facebook' => ['https://facebook.com/', 'https://www.facebook.com/'],
        'line' => ['https://line.me/ti/p/'],
        'instagram' => ['https://instagram.com/', 'https://www.instagram.com/'],
        'whatsApp' => ['https://wa.me/', 'wa.me/'],
        'linktree' => ['https://linktr.ee/', 'linktr.ee/'],
        'email' => ['mailto:']
    ];

    // Function to validate and process URL
    function validateAndProcessURL($platform, $url, $platformUrls)
    {
        if (empty($platform) || empty($url)) {
            return '';
        }

        // First validate for danger
        validateSmartURL($url, "contact URL");

        // Check if it's a full URL
        if (preg_match('/^https?:\/\/|^mailto:/', $url)) {

            // Validate it starts with one of the allowed URLs for this platform
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

            // Extract the username part after the base URL
            foreach ($validUrls as $validUrl) {
                if (strpos($url, $validUrl) === 0) {
                    $username = substr($url, strlen($validUrl));
                    // Sanitize the username
                    return preg_replace('/[^a-zA-Z0-9\-_.@]/', '', $username);
                }
            }
        } else {

            return preg_replace('/[^a-zA-Z0-9\-_.@]/', '', $url);
        }

        return '';
    }

    // Process URLs
    $URL = validateAndProcessURL($contact, $URL, $platformUrls);
    $URL2 = validateAndProcessURL($contact2, $URL2, $platformUrls);
    $URL3 = validateAndProcessURL($contact3, $URL3, $platformUrls);

    // Validate YouTube video URL if provided
    if (!empty($video)) {
        // First validate for danger
        validateSmartURL($video, "YouTube video");

        // Only accept standard YouTube watch URLs or youtu.be URLs
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
            die("Invalid YouTube URL. Please use a standard YouTube link (youtube.com/watch?v=... or youtu.be/...).");
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

    // Validate all text fields for dangerous chars
    validateTextContent($name, 'Name');
    validateTextContent($header, 'Section 1 Header');
    validateTextContent($about, 'Section 1 Content');
    validateTextContent($header2, 'Section 2 Header');
    validateTextContent($lessons, 'Section 2 Content');
    validateTextContent($header3, 'Section 3 Header');
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

    // image validation
    if (!empty($_FILES['profileImage']['name'])) {
        $uploadDir = "uploads/";
        $uploadError = null;

        // Validate directory exists and is writable
        if (!is_dir($uploadDir) || !is_writable($uploadDir)) {
            $uploadError = "Upload directory error!";
        }
        // Check if tmp_name exists and is not empty
        elseif (empty($_FILES['profileImage']['tmp_name']) || !file_exists($_FILES['profileImage']['tmp_name'])) {
            $uploadError = "No file uploaded or upload failed!";
        } else {
            $fileKey = $userLogin . ".png";
            $targetFile = $uploadDir . $fileKey;

            // Validate file type using multiple methods
            $allowedTypes = ['image/png'];
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $fileType = $finfo->file($_FILES['profileImage']['tmp_name']);

            if (!in_array($fileType, $allowedTypes)) {
                $uploadError = "File is not a valid PNG image!";
            }
            // Check file size
            elseif ($_FILES['profileImage']['size'] > 2 * 1024 * 1024) {
                $uploadError = "File is too large! Max 2MB allowed.";
            } else {
                // Get and validate dimensions
                list($width, $height) = getimagesize($_FILES['profileImage']['tmp_name']);
                if ($width > 4000 || $height > 4000) {
                    $uploadError = "Image dimensions too large!";
                } else {
                    // Process safely
                    $image = @imagecreatefrompng($_FILES['profileImage']['tmp_name']);
                    if (!$image) {
                        $uploadError = "Invalid image content!";
                    } else {
                        // Create a new blank image
                        $newImage = imagecreatetruecolor($width, $height);
                        // Copy the uploaded image to new blank one
                        imagecopy($newImage, $image, 0, 0, 0, 0, $width, $height);
                        // Save the clean image
                        if (!imagepng($newImage, $targetFile)) {
                            $uploadError = "Error saving image.";
                        }
                        // Clean up
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
    INSERT INTO brunoTemp (
        userLogin, userHash, email, name, 
        contact, URL, contact2, URL2, contact3, URL3,
        header, about, header2, lessons, video, header3, booking,
        lesson1, lesson1Duration, lesson1Cost, lesson1Place,
        lesson2, lesson2Duration, lesson2Cost, lesson2Place,
        lesson3, lesson3Duration, lesson3Cost, lesson3Place,
        calUser, tags
    ) VALUES (
        ?, ?, ?, ?, 
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?
    )
");

    $stmt->bind_param(
        'sssssssssssssssssssssssssssssss',  // 31
        $userLogin,
        $userHash,
        $email,
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
        $tags
    );
    if ($stmt->execute()) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        // Try to send emails, but don't fail if they don't send
        try {
            sendUserConfirmationEmail($email, $lang);
            sendAdminNotificationEmail($userLogin, $email);
        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
        }

        unset($_SESSION['reg_userLogin']);
        unset($_SESSION['reg_userHash']);
        unset($_SESSION['reg_email']);
        unset($_SESSION['reg_code']);
        unset($_SESSION['reg_expiry']);
        unset($_SESSION['email_verified']);

        $submission_success = true;
    } else {
        $error = "Submission failed: " . $stmt->error;
    }
    $stmt->close();
}
?>
<!doctype html>
<html>

<head>
    <title>BrunoTutor.com - <?php echo $submission_success ? 'Profile Submitted' : 'Create Page'; ?></title>
    <meta charset="utf-8" />

    <link href="style.css" rel="stylesheet">
    <link href="userStyle.css" rel="stylesheet">
    <link href="sucStyle.css" rel="stylesheet">
    <link rel="icon" type="image/x-icon" href="home.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <?php if ($submission_success): ?>

    <?php endif; ?>
</head>

<body>
    <main class="main">
        <?php if ($submission_success): ?>
            <div class="success-container">
                <div class="success-icon">✓</div>
                <h1><?= e($lang['success']); ?></h1>
                <p><?= e($lang['thank']); ?></p>
                <p><?= e($lang['underReview']); ?></p>
                <p><?= e($lang['timeline']); ?></p>
                <a href="https://www.brunotutor.com" class="btn"><?= e($lang['home']); ?></a>
            </div>
        <?php else: ?>
            <div class="container">
                <h1 style="text-align: center; margin-bottom: 0;"><?= e($lang['create']); ?></h1>
                <p style="text-align: center; margin-top: 0;"><a href="example.php"><?= e($lang['example']); ?></a></p><br>

                <?php if (isset($error)): ?>
                    <div style="color: red; text-align: center; margin: 20px 0;">
                        <?= e($error) ?>
                    </div>
                <?php endif; ?>

                <form method="post" action="createTutor.php" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                    <div class="row">
                        <div class="col">
                            <label for="profileImage"><?= e($lang['photo']); ?></label><br>
                            <input type="file" name="profileImage" id="profileImage" accept="image/png" required>
                        </div>
                    </div>
                    <br>

                    <div class="row">
                        <div class="col">
                            <div class="inline-content">
                                <div>
                                    <input type="text" id="name" name="name" placeholder="<?= e($lang['name']); ?>" style="font-size: 2rem; margin-bottom: 0;" required maxlength="30"><br>

                                    <div style="margin-top: 10px; display: flex; gap: 15px; flex-wrap: wrap;">
                                        <!-- Contact Link 1 (Required) -->
                                        <div style="flex: 1; min-width: 250px;">
                                            <select id="contact" name="contact" required style="width: 100%; margin-bottom: 5px;">
                                                <option value=""><?= e($lang['link']); ?>:</option>
                                                <option value="youtube">YouTube</option>
                                                <option value="facebook">Facebook</option>
                                                <option value="line">Line</option>
                                                <option value="instagram">Instagram</option>
                                                <option value="whatsApp">WhatsApp</option>
                                                <option value="linktree">Linktree</option>
                                                <option value="email">Email</option>
                                            </select>
                                            <input type="text" id="URL" name="URL" placeholder="URL or username/ID" maxlength="99" required style="width: 100%;">
                                            <small id="url1Error" style="color: red; display: none;"><?= e($lang['URLError']); ?></small>
                                        </div>

                                        <!-- Contact Link 2 (Optional) -->
                                        <div style="flex: 1; min-width: 250px;">
                                            <select id="contact2" name="contact2" style="width: 100%; margin-bottom: 5px;">
                                                <option value=""><?= e($lang['link']); ?> 2 <?= e($lang['optional']); ?>:</option>
                                                <option value="youtube">YouTube</option>
                                                <option value="facebook">Facebook</option>
                                                <option value="line">Line</option>
                                                <option value="instagram">Instagram</option>
                                                <option value="whatsApp">WhatsApp</option>
                                                <option value="linktree">Linktree</option>
                                                <option value="email">Email</option>
                                            </select>
                                            <input type="text" id="URL2" name="URL2" placeholder="URL or username/ID" maxlength="99" style="width: 100%;">
                                            <small id="url2Error" style="color: red; display: none;"><?= e($lang['URLError']); ?></small>
                                        </div>

                                        <!-- Contact Link 3 (Optional) -->
                                        <div style="flex: 1; min-width: 250px;">
                                            <select id="contact3" name="contact3" style="width: 100%; margin-bottom: 5px;">
                                                <option value=""><?= e($lang['link']); ?> 3 <?= e($lang['optional']); ?>:</option>
                                                <option value="youtube">YouTube</option>
                                                <option value="facebook">Facebook</option>
                                                <option value="line">Line</option>
                                                <option value="instagram">Instagram</option>
                                                <option value="whatsApp">WhatsApp</option>
                                                <option value="linktree">Linktree</option>
                                                <option value="email">Email</option>
                                            </select>
                                            <input type="text" id="URL3" name="URL3" placeholder="URL or username/ID" maxlength="99" style="width: 100%;">
                                            <small id="url3Error" style="color: red; display: none;"><?= e($lang['URLError']); ?></small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>

                    <!-- Headers and Content -->
                    <div class="row" style="margin-top: 1.5rem;">
                        <div class="col">
                            <input type="text" id="header" name="header" placeholder="<?= e($lang['header']); ?> 1 ('<?= e($lang['about']); ?>'<?= e($lang['etc']); ?>)" maxlength="30" required style="width: 100%; font-size: 1.5rem; font-weight: bold; margin-bottom: 10px;">
                            <textarea style="width: 100%; height: 70%;" id="about" name="about" placeholder="<?= e($lang['content']); ?>..." rows="5" maxlength="1200" required></textarea>
                        </div>
                        <div class="col">
                            <input type="text" id="header2" name="header2" placeholder="<?= e($lang['header']); ?> 2 ('<?= e($lang['lesson']); ?>'<?= e($lang['etc']); ?>) <?= e($lang['optional']); ?>" maxlength="30" style="width: 100%; font-size: 1.5rem; font-weight: bold; margin-bottom: 10px;">
                            <textarea style="width: 100%;" id="lessons" name="lessons" placeholder="<?= e($lang['content']); ?>... <?= e($lang['optional']); ?>" rows="5" maxlength="1200"></textarea>
                            <br>

                            <label for="video"><strong><?= e($lang['video']); ?> <?= e($lang['optional']); ?>:</strong></label><br>
                            <input type="text" id="video" name="video" placeholder="https://www.youtube.com/watch?v=VIDEO_ID" style="width: 80%;" maxlength="99">

                            <br><small id="videoError" style="color: red; display: none;"><?= e($lang['URLError']); ?></small>
                        </div>
                    </div>
                    <br>

                    <div class="row" style="margin-top: 1.5rem;">
                        <div class="col" style="text-align: center;">
                            <input type="text" id="header3" name="header3" placeholder="<?= e($lang['header']); ?> 3 ('<?= e($lang['booking']); ?>'<?= e($lang['etc']); ?>) <?= e($lang['optional']); ?>" maxlength="30" style="text-align: center; font-size: 1.5rem; font-weight: bold; margin-bottom: 10px; width: 50%;">
                            <textarea id="booking" name="booking" rows="3" style="width: 80%;" placeholder="<?= e($lang['content']); ?>... <?= e($lang['optional']); ?>" maxlength="1200"></textarea>
                        </div>
                    </div>
                    <br>

                    <div class="buttons-container">
                        <div class="chunky-button">
                            <div class="button-content">
                                <div class="input-row">
                                    <input type="text" id="lesson1" name="lesson1" placeholder="<?= e($lang['lessonTitle']); ?> 1 <?= e($lang['optional']); ?>" style="margin: 0; font-size: 18px; color: #333;" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                    </svg>
                                    <input type="text" id="lesson1Dur" name="lesson1Dur" placeholder="<?= e($lang['duration']); ?>" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                    </svg>
                                    <input type="text" id="lesson1Cost" name="lesson1Cost" placeholder="<?= e($lang['cost']); ?>" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                    </svg>
                                    <input type="text" id="lesson1Place" name="lesson1Place" placeholder="<?= e($lang['place']); ?>" maxlength="20">
                                </div>
                            </div>
                        </div>

                        <div class="chunky-button">
                            <div class="button-content">
                                <div class="input-row">
                                    <input type="text" id="lesson2" name="lesson2" placeholder="<?= e($lang['lessonTitle']); ?> 2 <?= e($lang['optional']); ?>" style="margin: 0; font-size: 18px; color: #333;" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                    </svg>
                                    <input type="text" id="lesson2Dur" name="lesson2Dur" placeholder="<?= e($lang['duration']); ?>" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                    </svg>
                                    <input type="text" id="lesson2Cost" name="lesson2Cost" placeholder="<?= e($lang['cost']); ?>" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                    </svg>
                                    <input type="text" id="lesson2Place" name="lesson2Place" placeholder="<?= e($lang['place']); ?>" maxlength="20">
                                </div>
                            </div>
                        </div>

                        <div class="chunky-button">
                            <div class="button-content">
                                <div class="input-row">
                                    <input type="text" id="lesson3" name="lesson3" placeholder="<?= e($lang['lessonTitle']); ?> 3 <?= e($lang['optional']); ?>" style="margin: 0; font-size: 18px; color: #333;" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                    </svg>
                                    <input type="text" id="lesson3Dur" name="lesson3Dur" placeholder="<?= e($lang['duration']); ?>" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                    </svg>
                                    <input type="text" id="lesson3Cost" name="lesson3Cost" placeholder="<?= e($lang['cost']); ?>" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                    </svg>
                                    <input type="text" id="lesson3Place" name="lesson3Place" placeholder="<?= e($lang['place']); ?>" maxlength="20">
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>
                    <hr>

                    <div class="buttons-container" style="margin-top: 1.5rem; margin-bottom: 1.5; padding-top: 0; gap: 10px;">
                        <label for="calUser"><strong>Cal.com:</strong></label>
                        <input type="text" id="calUser" name="calUser" placeholder="Cal.com">
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
            </form>
            </div>
        <?php endif; ?>
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
                    // Find the invalid character
                    const invalidChar = value.split('').find(char => !allowedPattern.test(char));
                    alert(`${lang.error} "${invalidChar}" ${lang.only}`);
                    // Remove invalid characters
                    input.value = value.replace(/[^\p{L}\p{N}\s\-–—@,.;:!?¡¿*()\\/=+'\n\r]/gu, '');
                    return false;
                }
                return true;
            }

            // Apply validation to all text inputs and textareas EXCEPT URL fields
            const textInputs = document.querySelectorAll('input[type="text"]:not(#URL):not(#URL2):not(#URL3):not(#video), textarea');

            textInputs.forEach(input => {
                // Validate on paste
                input.addEventListener('paste', function(e) {
                    setTimeout(() => validateTextInput(this), 0);
                });

                // Validate on input
                input.addEventListener('input', function() {
                    validateTextInput(this);
                });

                // Validate on blur (when user leaves field)
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
            }

            // URL validation
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

            // Smart URL validation
            function validateSmartURL(url, errorElement) {
                if (!url) {
                    return true;
                }

                // Check for danger
                const dangerousProtocols = /^(javascript|data|vbscript|file|about):/i;
                if (dangerousProtocols.test(url.trim())) {
                    errorElement.textContent = lang.URLError;
                    errorElement.style.display = 'block';
                    return false;
                }

                // For full URLs, validate they start with safe protocols
                if (url.includes(':')) {
                    const safeProtocols = /^(https?|mailto):/i;
                    if (!safeProtocols.test(url.trim())) {
                        errorElement.textContent = lang.URLError;
                        errorElement.style.display = 'block';
                        return false;
                    }
                }

                // Check for null bytes and control characters
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

                // First check for danger
                if (!validateSmartURL(url, errorElement)) {
                    return false;
                }

                // Check if full URL
                if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('mailto:')) {
                    const validUrls = platformUrls[platform];
                    const isValid = validUrls.some(validUrl => url.startsWith(validUrl));

                    if (!isValid) {
                        errorElement.textContent = lang.URLError;
                        errorElement.style.display = 'block';
                        return false;
                    }
                } else {
                    // If username, validate it only contains safe characters
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

                // First check for danger
                if (!validateSmartURL(url, errorElement)) {
                    return false;
                }

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

            // Validate on input
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

            // Validate when platform changes
            contact1Select.addEventListener('change', function() {
                validateURL(this.value, url1Input.value, url1Error);
            });

            contact2Select.addEventListener('change', function() {
                validateURL(this.value, url2Input.value, url2Error);
            });

            contact3Select.addEventListener('change', function() {
                validateURL(this.value, url3Input.value, url3Error);
            });

            // Prevent form submission if validation fails
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

                    if (!file) {
                        return;
                    }

                    if (file.type !== 'image/png') {
                        alert(lang.imgError);
                        this.value = '';
                        return;
                    }

                    // Check file size (2MB = 2 * 1024 * 1024 bytes)
                    const maxSize = 2 * 1024 * 1024;
                    if (file.size > maxSize) {
                        alert(lang.imgError);
                        this.value = '';
                        return;
                    }

                    // Check image dimensions
                    const img = new Image();
                    const objectUrl = URL.createObjectURL(file);

                    img.onload = function() {
                        URL.revokeObjectURL(objectUrl);

                        if (img.width > 4000 || img.height > 4000) {
                            alert(lang.imgError);
                            profileImageInput.value = '';
                            return;
                        }

                        console.log('Image validated: ' + img.width + 'x' + img.height + ', ' + (file.size / 1024).toFixed(2) + 'KB');
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