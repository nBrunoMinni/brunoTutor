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

// Redirect if user hasn't verified their email
if (!isset($_SESSION['email_verified']) || $_SESSION['email_verified'] !== true) {
    header("Location: regTutor.php");
    exit;
}

$dbc = new mysqli($host, $username, $password, $database);
if ($dbc->connect_error) {
    die("Database connection failed: " . $dbc->connect_error);
}

// Fetch subjects
$stmt = $dbc->query("SELECT subject_name FROM subjects ORDER BY subject_name ASC");
$subjects = [];
while ($row = $stmt->fetch_assoc()) {
    $subjects[] = $row;
}

// HTML escaping, should apply this everywhere
function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

function sendUserConfirmationEmail($email)
{
    $to = $email;
    $subject = "BrunoTutor Profile Submitted";
    $message = "
    <html>
    <head>
        <title>Profile Submitted</title>
    </head>
    <body>
        <p>Thank you for submitting your tutor profile with BrunoTutor!</p>
        <p>Your profile is now under review. This process usually takes less than 48 hours.</p>
        <p>We'll send another email once your profile is processed.</p>
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
        <p><strong>Review:</strong> <a href='brunoTutor.com/sub.php?name={$userLogin}'>brunoTutor.com/sub.php?name={$userLogin}</a></p>
        
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
            $fileKey = $userLogin . ".png";
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
        INSERT INTO brunoTemp (
            userLogin, userHash, email, name, 
            contact, URL, contact2, URL2,
            about, lessons, booking,
            lesson1, lesson1Duration, lesson1Cost, lesson1Place,
            lesson2, lesson2Duration, lesson2Cost, lesson2Place,
            lesson3, lesson3Duration, lesson3Cost, lesson3Place,
            calUser, tags
        ) VALUES (
            ?, ?, ?, ?, 
            ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?
        )
    ");

    if (!$stmt) {
        die("Prepare failed: " . $dbc->error);
    }

    $stmt->bind_param(
        'sssssssssssssssssssssssss',
        $userLogin,
        $userHash,
        $email,
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
        $tags
    );

    if ($stmt->execute()) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        sendUserConfirmationEmail($email);
        sendAdminNotificationEmail($userLogin, $email);

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
                <h1>Profile Submitted Successfully!</h1>
                <p>Thank you for submitting your tutor profile to BrunoTutor.</p>
                <p>Your profile is now under review. This process usually takes less than 48 hours.</p>
                <p>We've sent a confirmation email to your registered email address.</p>
                <p>You'll receive another email when your profile is approved.</p>

                <a href="https://www.brunotutor.com" class="btn">Return home</a>
            </div>
        <?php else: ?>
            <div class="container">
                <h1 style="text-align: center;">Create Your Tutor Profile</h1>

                <?php if (isset($error)): ?>
                    <div style="color: red; text-align: center; margin: 20px 0;">
                        <strong>Error:</strong> <?= e($error) ?>
                    </div>
                <?php endif; ?>

                <?php if (isset($imageError)): ?>
                    <div style="color: red; text-align: center; margin: 20px 0;">
                        <strong>Image Error:</strong> <?= e($imageError) ?>
                    </div>
                <?php endif; ?>

                <form method="post" action="createTutor.php" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <div class="row">
                        <div class="col">
                            <label for="profileImage">Upload Profile Image (PNG only):</label><br>
                            <input type="file" name="profileImage" id="profileImage" accept="image/png" required>
                        </div>
                    </div> <br>
                    <div class="row">
                        <div class="col">
                            <div class="inline-content">
                                <div>
                                    <input type="text" id="name" name="name" placeholder="Name" style="font-size: 2rem; margin-bottom: 0;" required maxlength="30"><br>
                                    <input type="text" id="contact" name="contact" placeholder="Contact 1" maxlength="30" required>
                                    <input type="text" id="contact2" name="contact2" placeholder="Contact 2" maxlength="30"><br>
                                    <input type="text" id="URL" name="URL" placeholder="Link 1" maxlength="50">
                                    <input type="text" id="URL2" name="URL2" placeholder="Link 2" maxlength="50">
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="row" style="margin-top: 1.5rem;">
                        <div class="col">
                            <h2>About Me</h2>
                            <textarea style="width: 100%;" id="about" name="about" placeholder="About me... (you can use * for *italics* and ** for **bold** in these sections)" rows="5" maxlength="1200" required></textarea>
                        </div>
                        <div class="col">
                            <h2>Lessons</h2>
                            <textarea style="width: 100%;" id="lessons" name="lessons" placeholder="Lessons..." rows="5" maxlength="1200" required></textarea>
                        </div>
                    </div>

                    <div class="row" style="margin-top: 1.5rem;">
                        <div class="col" style="text-align: center;">
                            <h2>Booking</h2>
                            <textarea id="booking" name="booking" rows="3" style="width: 80%;" placeholder="Bookings... (opt.)" maxlength="500"></textarea>
                        </div>
                    </div><br>

                    <div class="buttons-container">
                        <div class="chunky-button">
                            <div class="button-content">
                                <div class="input-row">
                                    <input type="text" id="lesson1" name="lesson1" placeholder="Lesson 1 title" style="margin: 0; font-size: 18px; color: #333;" required maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                    </svg>
                                    <input type="text" id="lesson1Dur" name="lesson1Dur" placeholder="Lesson 1 duration" required maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                    </svg>
                                    <input type="text" id="lesson1Cost" name="lesson1Cost" placeholder="Lesson 1 cost" required maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                    </svg>
                                    <input type="text" id="lesson1Place" name="lesson1Place" placeholder="Lesson 1 place" required maxlength="20">
                                </div>
                            </div>
                        </div>
                        <div class="chunky-button">
                            <div class="button-content">
                                <div class="input-row">
                                    <input type="text" id="lesson2" name="lesson2" placeholder="Lesson 2 title (opt.)" style="margin: 0; font-size: 18px; color: #333;" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                    </svg>
                                    <input type="text" id="lesson2Dur" name="lesson2Dur" placeholder="Lesson 2 duration (opt.)" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                    </svg>
                                    <input type="text" id="lesson2Cost" name="lesson2Cost" placeholder="Lesson 2 cost (opt.)" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                    </svg>
                                    <input type="text" id="lesson2Place" name="lesson2Place" placeholder="Lesson 2 place (opt.)" maxlength="20">
                                </div>
                            </div>
                        </div>
                        <div class="chunky-button">
                            <div class="button-content">
                                <div class="input-row">
                                    <input type="text" id="lesson3" name="lesson3" placeholder="Lesson 3 title (opt.)" style="margin: 0; font-size: 18px; color: #333;" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                    </svg>
                                    <input type="text" id="lesson3Dur" name="lesson3Dur" placeholder="Lesson 3 duration (opt.)" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                    </svg>
                                    <input type="text" id="lesson3Cost" name="lesson3Cost" placeholder="Lesson 3 cost (opt.)" maxlength="20">
                                </div>
                                <div class="input-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                    </svg>
                                    <input type="text" id="lesson3Place" name="lesson3Place" placeholder="Lesson 3 place (opt.)" maxlength="20">
                                </div>
                            </div>
                        </div>
                    </div>
                    <br>
                    <hr>

                    <div class="buttons-container" style="margin-top: 1.5rem; margin-bottom: 1.5rem; padding-top: 0; gap: 10px;">
                        <label for="calUser"><strong>Cal.com:</strong></label>
                        <input type="text" id="calUser" name="calUser" placeholder="Cal.com" required>
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
                <button type="submit" class="save">Submit Profile</button>
            </div>

            </form>
            </div>
        <?php endif; ?>
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

            // Skip if on the success page
            if (!selectBox) return;
            const defaultText = "Select up to 3 tags (opt.)";

            selectBox.addEventListener("click", function(event) {
                event.stopPropagation();
                customSelect.classList.toggle("active");
            });

            // Close dropdown when clicking outside
            document.addEventListener("click", function(event) {
                if (!customSelect.contains(event.target)) {
                    customSelect.classList.remove("active");
                }
            });

            // Update selection
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
        });
    </script>
</body>

</html>