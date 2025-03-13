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
    die("DB connection failed: " . $dbc->connect_error);
}
function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}
function sendResetEmail($email, $code)
{
    $to = $email;
    $subject = "BrunoTutor Password Reset";
    $message = "
    <html>
    <head>
        <title>Password Reset</title>
    </head>
    <body>
        <p>You have requested to reset your BrunoTutor password.</p>
        <p>Your verification code is: <strong>{$code}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        <p>If you did not request this password reset, please ignore this email.</p>
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
    $emailSent = sendResetEmail($_SESSION['reset_email'], $verificationCode);
    if ($emailSent) {
        $success = "A new verification code has been sent to your email.";
    } else {
        $error = "Failed to send verification email. Please try again.";
    }
}
// Request password reset
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['request_reset'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Security validation failed. Please try again.";
    } else {
        $email = $_POST['email'] ?? '';
        if (empty($email)) {
            $error = "Email address is required.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Please enter a valid email address.";
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
                $emailSent = sendResetEmail($email, $verificationCode);
                if ($emailSent) {
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    header("Location: reset.php?verify=1");
                    exit;
                } else {
                    $error = "Failed to send verification email. Please try again.";
                }
            } else {
                // Log even nothing attempts
                $success = "If your email is registered, you will receive a password reset code shortly.";
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
        $error = "Security validation failed. Please try again.";
    } else {
        $enteredCode = $_POST['verification_code'] ?? '';
        if (!isset($_SESSION['reset_code']) || !isset($_SESSION['reset_expiry'])) {
            $error = "Verification session expired. Please start over.";
        } elseif (time() > $_SESSION['reset_expiry']) {
            $error = "Verification code has expired. Please start over.";
            unset($_SESSION['reset_code']);
            unset($_SESSION['reset_expiry']);
            unset($_SESSION['reset_attempts']);
        } elseif ($enteredCode !== $_SESSION['reset_code']) {
            if (!isset($_SESSION['reset_attempts'])) {
                $_SESSION['reset_attempts'] = 0;
            }
            $_SESSION['reset_attempts']++;
            if ($_SESSION['reset_attempts'] >= 3) {
                $error = "Too many failed attempts. Your verification code has been invalidated for security reasons. Please request a new code.";

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
                $error = "Invalid verification code. Please try again. You have {$remainingAttempts} attempts remaining.";
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
        $error = "Security validation failed. Please try again.";
    } else {
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        if (!isset($_SESSION['reset_verified']) || $_SESSION['reset_verified'] !== true) {
            $error = "Unauthorized access. Please start the password reset process again.";
        } elseif (empty($newPassword) || empty($confirmPassword)) {
            $error = "Both password fields are required.";
        } elseif ($newPassword !== $confirmPassword) {
            $error = "Passwords do not match. Please try again.";
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
                $success = "Your password has been successfully reset. You can now log in with your new password.";
            } else {
                $error = "Failed to update password. Please try again.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>

<head>
    <title>BrunoTutor.com - Reset Password</title>
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
                <p style="color:red;"><strong>Error:</strong> <?= e($error) ?></p>
            <?php endif; ?>
            <?php if (!empty($success)): ?>
                <div class="success-container">
                    <div class="success-icon">✓</div>
                    <p style="color:green;"><strong>Success:</strong> <?= e($success) ?></p>
                    <p style="text-align: center; margin-top: 20px;">
                        <a href="editTutor.php">Return to Login</a>
                    </p>
                </div>
            <?php elseif (isset($_GET['new_password']) && isset($_SESSION['reset_verified'])): ?>
                <h1>Set New Password</h1>
                <p>Please enter your new password:</p>
                <div class="form-container">
                    <form method="post" action="reset.php?new_password=1">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <label for="new_password">New Password:</label>
                            <input type="password" name="new_password" id="new_password" required>
                        </div>
                        <div>
                            <label for="confirm_password">Confirm Password:</label>
                            <input type="password" name="confirm_password" id="confirm_password" required>
                        </div>
                        <button type="submit" name="reset_password">Reset Password</button>
                    </form>
                </div>
            <?php elseif (isset($_GET['verify'])): ?>
                <h1>Verify Your Email</h1>
                <p>A verification code has been sent to <strong><?= e($_SESSION['reset_email'] ?? '') ?></strong></p>
                <p>Please enter the 6-digit code to continue:</p>
                <div class="form-container">
                    <form method="post" action="reset.php?verify=1">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <input type="text" name="verification_code" class="verification-input"
                                maxlength="6" pattern="[0-9]{6}" placeholder="000000" required>
                        </div>
                        <button type="submit" name="verify">Verify Code</button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        <a href="reset.php">Back to Reset Password</a>
                        <?php if (isset($_SESSION['reset_attempts']) && $_SESSION['reset_attempts'] > 0): ?>
                            <br><small>Failed attempts: <?= $_SESSION['reset_attempts'] ?>/3</small>
                        <?php endif; ?>
                        <?php if (!isset($_SESSION['reset_code']) || (isset($_SESSION['reset_attempts']) && $_SESSION['reset_attempts'] >= 3)): ?>
                            <br><a href="reset.php?resend=1">Request a new code</a>
                        <?php endif; ?>
                    </p>
                </div>
            <?php else: ?>
                <h1>Reset Password</h1>
                <p>Enter your email address to receive reset link:</p>
                <div class="form-container">
                    <form method="post" action="reset.php">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <label for="email">Email:</label>
                            <input type="email" name="email" id="email" value="<?= e($email) ?>" required>
                        </div>
                        <button type="submit" name="request_reset">Request Reset</button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        Remember your password? <a href="editTutor.php">Login here</a>
                    </p>
                </div>
            <?php endif; ?>
        </div>
    </main>
    <footer class="footer">
        <small><a href="https://www.brunotutor.com">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
        <small><a href="https://www.brunotutor.com/regTutor.php">Create page</a> • <a href="https://www.brunotutor.com/tos.php">Terms of service</a></small>
    </footer>
</body>

</html>