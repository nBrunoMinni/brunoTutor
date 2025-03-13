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

$dbc = new mysqli($host, $username, $password, $database);
if ($dbc->connect_error) {
    die("Database connection failed");
}

$stmt = $dbc->prepare("SELECT subject_name FROM subjects ORDER BY subject_name ASC");
$stmt->execute();
$result = $stmt->get_result();
$subjects = [];
while ($row = $result->fetch_assoc()) {
    $subjects[] = $row;
}

// HTML escaping, should apply this everywhere
function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: editTutor.php");
    exit;
}
if (isset($_POST['login'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $loginError = "Security token validation failed. Please try again.";
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

            // 30 minute (1800 seconds) lockout
            if ($timeElapsed < 1800) {
                $accountLocked = true;
                $loginError = "Too many failed attempts. Please click 'Forgot Password?' to reset your password.";
            } else {
                // Reset counter after
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

                    // Redirect to avoid form resubmission
                    header("Location: editTutor.php");
                    exit;
                } else {
                    updateLoginAttempts($dbc, $inputUser);
                    $loginError = "Invalid username or password.";
                }
            } else {
                updateLoginAttempts($dbc, $inputUser);
                $loginError = "Invalid username or password.";
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
        <title>Tutor Login</title>
        <meta charset="utf-8" />
        <link href="style.css" rel="stylesheet">
        <link href="logStyle.css" rel="stylesheet">
        <link rel="icon" type="image/x-icon" href="home.ico">
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>

    <body>
        <main class="main">
            <div class="container" style="max-width: 400px; margin: 0 auto; text-align: center;">
                <h1>Tutor Login</h1>
                <?php if (!empty($loginError)): ?>
                    <p style="color: red; text-align:center;">
                        <strong><?= e($loginError) ?></strong>
                    </p>
                <?php endif; ?>
                <div class="form-container">
                    <form method="post" action="editTutor.php">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                        <div>
                            <label for="userLogin">Username:</label>
                            <input type="text" name="userLogin" id="userLogin" required>
                        </div>
                        <div>
                            <label for="userPassword">Password:</label>
                            <input type="password" name="userPassword" id="userPassword" style="margin-bottom: 5px;" required>
                            <div style="text-align: right; font-size: 0.8em; margin-top: 0;">
                                <a href="reset.php">Forgot Password?</a>
                            </div>
                        </div>
                        <button type="submit" name="login" class="login-btn">Login</button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        Don't have an account? <a href="regTutor.php">Register here</a>
                    </p>
                </div>
            </div>
        </main>
        <footer class="footer">
            <small><a href="https://www.brunotutor.com">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
            <small><a href="https://www.brunotutor.com/regTutor.php">Create page</a> • <a href="https://www.brunotutor.com/tos.php">Terms of service</a></small>
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
    $about        = $_POST['about']        ?? '';
    $lessons      = $_POST['lessons']      ?? '';
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
            $fileKey = $_SESSION['tutorLogin'] . ".png";
            $targetFile = $uploadDir . $fileKey;

            // Validate file type using multiple methods
            $allowedTypes = ['image/png'];
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $fileType = $finfo->file($_FILES['profileImage']['tmp_name']);

            if (!in_array($fileType, $allowedTypes)) {
                $uploadError = "File is not a valid PNG image!";
            }
            // Check file size (2MB limit)
            elseif ($_FILES['profileImage']['size'] > 2 * 1024 * 1024) {
                $uploadError = "File is too large! Max 2MB allowed.";
            } else {
                // Get and validate image dimensions
                list($width, $height) = getimagesize($_FILES['profileImage']['tmp_name']);
                if ($width > 2000 || $height > 2000) {
                    $uploadError = "Image dimensions too large!";
                } else {
                    // Process the image safely
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
        UPDATE bruno 
        SET 
            name = ?, 
            contact = ?, 
            URL = ?, 
            contact2 = ?, 
            URL2 = ?, 
            about = ?, 
            lessons = ?, 
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
        'sssssssssssssssssssssss',
        $name,
        $contact,
        $URL,
        $contact2,
        $URL2,
        $about,
        $lessons,
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
        $updateMessage = "Changes saved!";
        $stmt2 = $dbc->prepare("SELECT * FROM bruno WHERE userLogin = ? LIMIT 1");
        $stmt2->bind_param('s', $_SESSION['tutorLogin']);
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        if ($res2 && $res2->num_rows === 1) {
            $_SESSION['tutorRow'] = $res2->fetch_assoc();
        }
        $stmt2->close();
    } else {
        $updateMessage = "Update failed.";
    }
    $stmt->close();
}

$row = $_SESSION['tutorRow'] ?? null;
if (!$row) {
    // Just in case
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
$about        = $row['about']            ?? '';
$lessons      = $row['lessons']          ?? '';
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
    <title>BrunoTutor.com - Edit <?= e($name ?: $_SESSION['tutorLogin']) ?></title>
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
                <div class="row">
                    <div class="col">
                        <label for="profileImage">Upload Profile Image (PNG only):</label><br>
                        <input type="file" name="profileImage" id="profileImage" accept="image/png">
                    </div>
                </div> <br>
                <div class="row">
                    <div class="col">
                        <div class="inline-content">
                            <?php
                            $uploadedImage = "uploads/" . ($_SESSION['tutorLogin'] ?? 'default') . ".png";
                            if (!file_exists($uploadedImage)) {
                                $uploadedImage = "default.png";
                            }
                            ?>
                            <img src="<?= e($uploadedImage) ?>" alt="Profile Image" width="150">
                            <div>
                                <input type="text" id="name" name="name" placeholder="Name" style="font-size: 2rem; margin-bottom: 0;" value="<?= e($name) ?>" required maxlength="30"><br>
                                <input type="text" id="contact" name="contact" placeholder="Contact 1" maxlength="30" value="<?= e($contact) ?>" required>
                                <input type="text" id="contact2" name="contact2" placeholder="Contact 2" maxlength="30" value="<?= e($contact2) ?>"><br>
                                <input type="text" id="URL" name="URL" placeholder="Link 1" maxlength="50" value="<?= e($URL) ?>">
                                <input type="text" id="URL2" name="URL2" placeholder="Link 2" maxlength="50" value="<?= e($URL2) ?>">
                            </div>
                        </div>
                    </div>
                </div>
                <div class="row" style="margin-top: 1.5rem;">
                    <div class="col">
                        <h2>About Me</h2>
                        <textarea style="width: 100%;" id="about" name="about" placeholder="About me... (you can use * for *italics* and ** for **bold** in these sections)" rows="5" maxlength="1200" required><?= e($about) ?></textarea>
                    </div>
                    <div class="col">
                        <h2>Lessons</h2>
                        <textarea style="width: 100%;" id="lessons" name="lessons" placeholder="Lessons..." rows="5" maxlength="1200" required><?= e($lessons) ?></textarea>
                    </div>
                </div>
                <div class="row" style="margin-top: 1.5rem;">
                    <div class="col" style="text-align: center;">
                        <h2>Booking</h2>
                        <textarea id="booking" name="booking" rows="3" style="width: 80%;" placeholder="Bookings... (opt.)" maxlength="500"><?= e($booking) ?></textarea>
                    </div>
                </div><br>
                <div class="buttons-container">
                    <div class="chunky-button">
                        <div class="button-content">
                            <div class="input-row">
                                <input type="text" id="lesson1" name="lesson1" placeholder="Lesson 1 title" style="margin: 0; font-size: 18px; color: #333;" value="<?= e($lesson1) ?>" required maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <input type="text" id="lesson1Dur" name="lesson1Dur" placeholder="Lesson 1 duration" value="<?= e($lesson1Dur) ?>" required maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <input type="text" id="lesson1Cost" name="lesson1Cost" placeholder="Lesson 1 cost" value="<?= e($lesson1Cost) ?>" required maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <input type="text" id="lesson1Place" name="lesson1Place" placeholder="Lesson 1 place" value="<?= e($lesson1Place) ?>" required maxlength="20">
                            </div>
                        </div>
                    </div>
                    <div class="chunky-button">
                        <div class="button-content">
                            <div class="input-row">
                                <input type="text" id="lesson2" name="lesson2" placeholder="Lesson 2 title (opt.)" style="margin: 0; font-size: 18px; color: #333;" value="<?= e($lesson2) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <input type="text" id="lesson2Dur" name="lesson2Dur" placeholder="Lesson 2 duration (opt.)" value="<?= e($lesson2Dur) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <input type="text" id="lesson2Cost" name="lesson2Cost" placeholder="Lesson 2 cost (opt.)" value="<?= e($lesson2Cost) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <input type="text" id="lesson2Place" name="lesson2Place" placeholder="Lesson 2 place (opt.)" value="<?= e($lesson2Place) ?>" maxlength="20">
                            </div>
                        </div>
                    </div>
                    <div class="chunky-button">
                        <div class="button-content">
                            <div class="input-row">
                                <input type="text" id="lesson3" name="lesson3" placeholder="Lesson 3 title (opt.)" style="margin: 0; font-size: 18px; color: #333;" value="<?= e($lesson3) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <input type="text" id="lesson3Dur" name="lesson3Dur" placeholder="Lesson 3 duration (opt.)" value="<?= e($lesson3Dur) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <input type="text" id="lesson3Cost" name="lesson3Cost" placeholder="Lesson 3 cost (opt.)" value="<?= e($lesson3Cost) ?>" maxlength="20">
                            </div>
                            <div class="input-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <input type="text" id="lesson3Place" name="lesson3Place" placeholder="Lesson 3 place (opt.)" value="<?= e($lesson3Place) ?>" maxlength="20">
                            </div>
                        </div>
                    </div>
                </div>
                <br>
                <hr>
                <div class="buttons-container" style="margin-top: 1.5rem; margin-bottom: 1.5rem; padding-top: 0; gap: 10px;">
                    <label for="calUser"><strong>Cal.com:</strong></label>
                    <input type="text" id="calUser" name="calUser" placeholder="Cal.com" value="<?= e($calUser) ?>" required>
                </div>
                <div class="buttons-container" style="margin-top: 1.5rem; margin-bottom: 1.5rem; padding-top: 0; gap: 10px;">
                    <div class="custom-select" id="customSelect">
                        <div class="select-box" id="selectBox">Select up to 3 tags (opt.)</div>
                        <div class="checkbox-dropdown">
                            <?php foreach ($subjects as $subject): ?>
                                <label>
                                    <input type="checkbox" value="<?= htmlspecialchars($subject['subject_name']) ?>">
                                    <?= htmlspecialchars($subject['subject_name']) ?>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
                <input type="hidden" name="tags" id="tagsHidden">
        </div>

        <div class="buttons-container" style="display: flex; gap: 10px;">
            <label>
                <input type="checkbox" id="tosCheckbox" required>
                I confirm that the above content meets the <a href="https://www.brunotutor.com/tos.php" target="_blank">terms of service</a>
            </label>
        </div>

        <div class="buttons-container" style="display: flex; gap: 10px;">
            <button type="submit" class="save">Save</button>
        </div>


        <div class="buttons-container" style="display: flex; gap: 10px;">
            <a href="editTutor.php?logout=1" style="color: #FF7276;">Log Out</a>
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
                        setTimeout(() => alertBox.remove(), 1000); // Remove from DOM after fade
                    }, 3000);
                });
            </script>
        <?php endif; ?>
        </form>
        </div>
    </main>

    <footer class="footer">
        <small><a href="https://www.brunotutor.com">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
        <small><a href="https://www.brunotutor.com/regTutor.php">Create page</a> • <a href="https://www.brunotutor.com/tos.php">Terms of service</a></small>
    </footer>

    <script>
        document.addEventListener("DOMContentLoaded", function() {
            const selectBox = document.getElementById("selectBox");
            const customSelect = document.getElementById("customSelect");
            const checkboxes = document.querySelectorAll(".checkbox-dropdown input[type='checkbox']");
            const hiddenInput = document.getElementById("tagsHidden");
            const defaultText = "Select up to 3 tags (opt.)";

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
                        alert("You can select up to 3 tags only.");
                        this.checked = false;
                        return;
                    }
                    selectBox.innerText = selected.length ? selected.join(", ") : defaultText;
                    hiddenInput.value = selected.join(", ");
                });
            });
            let preselectedTags = "<?= e($tags) ?>".split(", ").filter(tag => tag.trim() !== "");
            checkboxes.forEach(checkbox => {
                if (preselectedTags.includes(checkbox.value)) {
                    checkbox.checked = true;
                }
            });
            selectBox.innerText = preselectedTags.length > 0 ? preselectedTags.join(", ") : defaultText;
            hiddenInput.value = preselectedTags.length > 0 ? preselectedTags.join(", ") : "";
        });
    </script>
</body>

</html>