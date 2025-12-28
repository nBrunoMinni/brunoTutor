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
    die("DB connection failed: " . $dbc->connect_error);
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

function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

function sendResetEmail($email, $code, $lang)
{
    $to = $email;
    $subject = "BrunoTutor " . $lang['reset'];
    $message = "
    <html>
    <head>
        <title>" . htmlspecialchars($lang['reset'], ENT_QUOTES, 'UTF-8') . "</title>
    </head>
    <body>
        <p>" . htmlspecialchars($lang['youHaveRequested'], ENT_QUOTES, 'UTF-8') . "</p>
        <p>" . htmlspecialchars($lang['code'], ENT_QUOTES, 'UTF-8') . " <strong>{$code}</strong></p>
        <p>" . htmlspecialchars($lang['expire'], ENT_QUOTES, 'UTF-8') . "</p>
    </body>
    </html>
    ";
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= 'From: no-reply@brunotutor.com' . "\r\n";
    return mail($to, $subject, $message, $headers);
}

function generateVerificationCode()
{
    return str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

$email = "";
$error = "";
$success = "";

// Generate a new verification code
if (isset($_GET['resend']) && isset($_SESSION['reset_email'])) {
    $verificationCode = generateVerificationCode();
    $expiryTime = time() + 600; // 10 minutes 
    $_SESSION['reset_code'] = $verificationCode;
    $_SESSION['reset_expiry'] = $expiryTime;
    $_SESSION['reset_attempts'] = 0; // Reset attempts
    $emailSent = sendResetEmail($_SESSION['reset_email'], $verificationCode, $lang);
    if ($emailSent) {
        $success = $lang['verificationSent'];
    } else {
        $error = $lang['failed'];
    }
}

// Request password reset
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['request_reset'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = $lang['failed'];
    } else {
        $email = $_POST['email'] ?? '';
        if (empty($email)) {
            $error = $lang['required'];
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = $lang['emailValid'];
        } else {
            $stmtCheck = $dbc->prepare("SELECT userLogin FROM bruno WHERE email = ? LIMIT 1");
            $stmtCheck->bind_param("s", $email);
            $stmtCheck->execute();
            $resCheck = $stmtCheck->get_result();
            if ($resCheck && $resCheck->num_rows > 0) {
                $row = $resCheck->fetch_assoc();
                $userLogin = $row['userLogin'];
                $verificationCode = generateVerificationCode();
                $expiryTime = time() + 600; // 10 minutes from now
                $_SESSION['reset_email'] = $email;
                $_SESSION['reset_userLogin'] = $userLogin;
                $_SESSION['reset_code'] = $verificationCode;
                $_SESSION['reset_expiry'] = $expiryTime;
                $_SESSION['reset_attempts'] = 0;
                $currentTime = date('Y-m-d H:i:s');
                $ipAddress = $_SERVER['REMOTE_ADDR'];
                $stmtLog = $dbc->prepare("INSERT INTO password_reset_log (userLogin, email, request_time, ip_address, status) VALUES (?, ?, ?, ?, ?)");
                $status = "requested";
                $stmtLog->bind_param("sssss", $userLogin, $email, $currentTime, $ipAddress, $status);
                $stmtLog->execute();
                $_SESSION['reset_log_id'] = $dbc->insert_id; // Store the log ID
                $stmtLog->close();
                $emailSent = sendResetEmail($email, $verificationCode, $lang);
                if ($emailSent) {
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    header("Location: reset.php?verify=1");
                    exit;
                } else {
                    $error = $lang['failed'];
                }
            } else {
                // Log even nothing attempts
                $success = $lang['ifYourEmail'];
                $currentTime = date('Y-m-d H:i:s');
                $ipAddress = $_SERVER['REMOTE_ADDR'];
                $status = "invalid_email";
                $stmtLog = $dbc->prepare("INSERT INTO password_reset_log (userLogin, email, request_time, ip_address, status) VALUES (?, ?, ?, ?, ?)");
                $nonExistentUser = "unknown";
                $stmtLog->bind_param("sssss", $nonExistentUser, $email, $currentTime, $ipAddress, $status);
                $stmtLog->execute();
                $stmtLog->close();
            }
            $stmtCheck->close();
        }
    }
}

// Verify email with code
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = $lang['failed'];
    } else {
        $enteredCode = $_POST['verification_code'] ?? '';
        if (!isset($_SESSION['reset_code']) || !isset($_SESSION['reset_expiry'])) {
            $error = $lang['verificationFail'];
        } elseif (time() > $_SESSION['reset_expiry']) {
            $error = $lang['verificationFail'];
            unset($_SESSION['reset_code']);
            unset($_SESSION['reset_expiry']);
            unset($_SESSION['reset_attempts']);
        } elseif ($enteredCode !== $_SESSION['reset_code']) {
            if (!isset($_SESSION['reset_attempts'])) {
                $_SESSION['reset_attempts'] = 0;
            }
            $_SESSION['reset_attempts']++;
            if ($_SESSION['reset_attempts'] >= 3) {
                $error = $lang['verificationFail'];
                // Log failed attempts
                if (isset($_SESSION['reset_log_id'])) {
                    $logId = $_SESSION['reset_log_id'];
                    $status = "failed_verification";
                    $stmtUpdateLog = $dbc->prepare("UPDATE password_reset_log SET status = ? WHERE id = ?");
                    $stmtUpdateLog->bind_param("si", $status, $logId);
                    $stmtUpdateLog->execute();
                    $stmtUpdateLog->close();
                }
                // Clear data
                unset($_SESSION['reset_code']);
                unset($_SESSION['reset_expiry']);
                unset($_SESSION['reset_attempts']);
            } else {
                $remainingAttempts = 3 - $_SESSION['reset_attempts'];
                $error = $lang['invalid'] . " {$remainingAttempts} " . $lang['attempts'];
            }
        } else {
            // Valid
            $_SESSION['reset_verified'] = true;
            unset($_SESSION['reset_attempts']);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            if (isset($_SESSION['reset_log_id'])) {
                $logId = $_SESSION['reset_log_id'];
                $status = "verified";
                $stmtUpdateLog = $dbc->prepare("UPDATE password_reset_log SET status = ? WHERE id = ?");
                $stmtUpdateLog->bind_param("si", $status, $logId);
                $stmtUpdateLog->execute();
                $stmtUpdateLog->close();
            }
            header("Location: reset.php?new_password=1");
            exit;
        }
    }
}

// Set new password
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_password'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = $lang['failed'];
    } else {
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        if (!isset($_SESSION['reset_verified']) || $_SESSION['reset_verified'] !== true) {
            $error = $lang['verificationFail'];
        } elseif (empty($newPassword) || empty($confirmPassword)) {
            $error = $lang['required'];
        } elseif ($newPassword !== $confirmPassword) {
            $error = $lang['passwordMatch'];
        } else {
            $userLogin = $_SESSION['reset_userLogin'];
            $userHash = password_hash($newPassword, PASSWORD_DEFAULT);
            $stmtUpdate = $dbc->prepare("UPDATE bruno SET userHash = ? WHERE userLogin = ?");
            $stmtUpdate->bind_param("ss", $userHash, $userLogin);
            $result = $stmtUpdate->execute();
            $stmtUpdate->close();
            if ($result) {
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                $stmtClearAttempts = $dbc->prepare("DELETE FROM login_attempts WHERE userLogin = ?");
                $stmtClearAttempts->bind_param('s', $userLogin);
                $stmtClearAttempts->execute();
                $stmtClearAttempts->close();
                if (isset($_SESSION['reset_log_id'])) {
                    $logId = $_SESSION['reset_log_id'];
                    $status = "completed";
                    $stmtUpdateLog = $dbc->prepare("UPDATE password_reset_log SET status = ? WHERE id = ?");
                    $stmtUpdateLog->bind_param("si", $status, $logId);
                    $stmtUpdateLog->execute();
                    $stmtUpdateLog->close();
                }
                unset($_SESSION['reset_email']);
                unset($_SESSION['reset_userLogin']);
                unset($_SESSION['reset_code']);
                unset($_SESSION['reset_expiry']);
                unset($_SESSION['reset_verified']);
                unset($_SESSION['reset_log_id']);
                $success = $lang['success'] . " " . $lang['reset'];
            } else {
                $error = $lang['failed'];
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>

<head>
    <title>BrunoTutor.com - <?= e($lang['reset']); ?></title>
    <link href="style.css" rel="stylesheet">
    <link href="logStyle.css" rel="stylesheet">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/x-icon" href="home.ico">
    <style>
        .success-container {
            max-width: 600px;
            margin: 40px auto;
            padding: 20px;
            text-align: center;
            background-color: #f9f9f9;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }

        .success-icon {
            font-size: 64px;
            color: #4CAF50;
            margin-bottom: 20px;
        }
    </style>
</head>

<body>
    <main class="main">
        <div class="container" style="max-width: 400px; margin: 0 auto; align-items: center; text-align: center;">
            <?php if (!empty($error)): ?>
                <p style="color:red;"><strong><?= e($lang['error']); ?></strong> <?= e($error) ?></p>
            <?php endif; ?>
            <?php if (!empty($success)): ?>
                <div class="success-container">
                    <div class="success-icon">✓</div>
                    <p style="color:green;"><strong><?= e($lang['success']); ?></strong> <?= e($success) ?></p>
                    <p style="text-align: center; margin-top: 20px;">
                        <a href="editTutor.php"><?= e($lang['login']); ?></a>
                    </p>
                </div>
            <?php elseif (isset($_GET['new_password']) && isset($_SESSION['reset_verified'])): ?>
                <h1><?= e($lang['setNewPassword']); ?></h1>
                <div class="form-container">
                    <form method="post" action="reset.php?new_password=1">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <label for="new_password"><?= e($lang['password']); ?></label>
                            <input type="password" name="new_password" id="new_password" required>
                        </div>
                        <div>
                            <label for="confirm_password"><?= e($lang['confirmPassword']); ?></label>
                            <input type="password" name="confirm_password" id="confirm_password" required>
                        </div>
                        <button type="submit" name="reset_password"><?= e($lang['reset']); ?></button>
                    </form>
                </div>
            <?php elseif (isset($_GET['verify'])): ?>
                <h1><?= e($lang['verify']); ?></h1>
                <p><?= e($lang['verificationSent']); ?> <strong><?= e($_SESSION['reset_email'] ?? '') ?></strong></p>
                <p><?= e($lang['pleaseEnter']); ?></p>
                <div class="form-container">
                    <form method="post" action="reset.php?verify=1">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <input type="text" name="verification_code" class="verification-input"
                                maxlength="6" pattern="[0-9]{6}" placeholder="000000" required>
                        </div>
                        <button type="submit" name="verify"><?= e($lang['verify']); ?></button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        <a href="reset.php"><?= e($lang['reset']); ?></a>
                        <?php if (isset($_SESSION['reset_attempts']) && $_SESSION['reset_attempts'] > 0): ?>
                            <br><small><?= e($lang['failedAttempts']); ?> <?= $_SESSION['reset_attempts'] ?>/3</small>
                        <?php endif; ?>
                        <?php if (!isset($_SESSION['reset_code']) || (isset($_SESSION['reset_attempts']) && $_SESSION['reset_attempts'] >= 3)): ?>
                            <br><a href="reset.php?resend=1"><?= e($lang['requestReset']); ?></a>
                        <?php endif; ?>
                    </p>
                </div>
            <?php else: ?>
                <h1><?= e($lang['reset']); ?></h1>
                <div class="form-container">
                    <form method="post" action="reset.php">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <label for="email"><?= e($lang['email']); ?></label>
                            <input type="email" name="email" id="email" value="<?= e($email) ?>" required>
                        </div>
                        <button type="submit" name="request_reset"><?= e($lang['requestReset']); ?></button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        <a href="editTutor.php"><?= e($lang['login']); ?></a>
                    </p>
                </div>
            <?php endif; ?>
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