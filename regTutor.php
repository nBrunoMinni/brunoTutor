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

// HTML escaping, should apply this everywhere
function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

function sendVerificationEmail($email, $code)
{
    $to = $email;
    $subject = "BrunoTutor Email Verification";
    $message = "
    <html>
    <head>
        <title>Email Verification</title>
    </head>
    <body>
        <p>Thank you for registering with BrunoTutor!</p>
        <p>Your verification code is: <strong>{$code}</strong></p>
        <p>This code will expire in 10 minutes.</p>
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

$userLogin = $email = "";
$error = "";

// STEP 1: Initial registration form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Security validation failed. Please try again.";
    } else {
        $userLogin = $_POST['userLogin'] ?? '';
        $plainPass = $_POST['userPassword'] ?? '';
        $confirmPass = $_POST['userPasswordConfirm'] ?? '';
        $email = $_POST['email'] ?? '';

        if (empty($userLogin) || empty($plainPass) || empty($confirmPass) || empty($email)) {
            $error = "All fields are required.";
        } elseif ($plainPass !== $confirmPass) {
            $error = "Passwords do not match. Please try again.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Please enter a valid email address.";
        } elseif (strlen($userLogin) > 20) {
            $error = "Username must be 20 characters or less.";
        } elseif (!preg_match('/^[a-z0-9-]+$/', $userLogin)) {
            $error = "Username can only contain lowercase letters, numbers, and dashes (-)";
        } else {
            // If username exists
            $stmtCheck = $dbc->prepare("SELECT 1 FROM bruno WHERE userLogin = ? LIMIT 1");
            $stmtCheck->bind_param("s", $userLogin);
            $stmtCheck->execute();
            $resCheck = $stmtCheck->get_result();
            if ($resCheck && $resCheck->num_rows > 0) {
                $error = "That username is already taken. Please choose another.";
            }
            $stmtCheck->close();

            $stmtCheckTemp = $dbc->prepare("SELECT 1 FROM brunoTemp WHERE userLogin = ? LIMIT 1");
            $stmtCheckTemp->bind_param("s", $userLogin);
            $stmtCheckTemp->execute();
            $resCheckTemp = $stmtCheckTemp->get_result();
            if ($resCheckTemp && $resCheckTemp->num_rows > 0) {
                $error = "That username is already taken. Please choose another.";
            }
            $stmtCheckTemp->close();

            // If email exists
            $stmtCheckEmailTemp = $dbc->prepare("SELECT 1 FROM bruno WHERE email = ? LIMIT 1");
            $stmtCheckEmailTemp->bind_param("s", $email);
            $stmtCheckEmailTemp->execute();
            $resCheckEmailTemp = $stmtCheckEmailTemp->get_result();
            if ($resCheckEmailTemp && $resCheckEmailTemp->num_rows > 0) {
                $error = "That email address is already registered.";
            }
            $stmtCheckEmailTemp->close();
        }

        if (empty($error)) {
            $verificationCode = generateVerificationCode();
            $expiryTime = time() + 600; // 10 minutes from now
            $userHash = password_hash($plainPass, PASSWORD_DEFAULT);

            $_SESSION['reg_userLogin'] = $userLogin;
            $_SESSION['reg_userHash'] = $userHash;
            $_SESSION['reg_email'] = $email;
            $_SESSION['reg_code'] = $verificationCode;
            $_SESSION['reg_expiry'] = $expiryTime;
            $_SESSION['reg_attempts'] = 0;

            $emailSent = sendVerificationEmail($email, $verificationCode);

            if ($emailSent) {
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                header("Location: regTutor.php?verify=1");
                exit;
            } else {
                $error = "Failed to send verification email. Please try again.";
            }
        }
    }
}

// STEP 2: Verify email with code
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Security validation failed. Please try again.";
    } else {
        $enteredCode = $_POST['verification_code'] ?? '';

        if (!isset($_SESSION['reg_code']) || !isset($_SESSION['reg_expiry'])) {
            $error = "Verification session expired. Please start over.";
        } elseif (time() > $_SESSION['reg_expiry']) {
            $error = "Verification code has expired. Please start over.";
            // Clear expired session
            unset($_SESSION['reg_code']);
            unset($_SESSION['reg_expiry']);
            unset($_SESSION['reg_attempts']);
        } elseif ($enteredCode !== $_SESSION['reg_code']) {

            if (!isset($_SESSION['reg_attempts'])) {
                $_SESSION['reg_attempts'] = 0;
            }

            $_SESSION['reg_attempts']++;
            if ($_SESSION['reg_attempts'] >= 3) {
                $error = "Too many failed attempts. Please start over.";
                unset($_SESSION['reg_code']);
                unset($_SESSION['reg_expiry']);
                unset($_SESSION['reg_attempts']);
            } else {
                $remainingAttempts = 3 - $_SESSION['reg_attempts'];
                $error = "Invalid verification code. Please try again. You have {$remainingAttempts} attempts remaining.";
            }
        } else {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['email_verified'] = true;
            unset($_SESSION['reg_attempts']); // Clear attempts counter on success
            header("Location: createTutor.php");
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html>

<head>
    <title>BrunoTutor.com - Register New Tutor</title>
    <link href="style.css" rel="stylesheet">
    <link href="logStyle.css" rel="stylesheet">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/x-icon" href="home.ico">
</head>

<body>
    <main class="main">
        <div class="container" style="max-width: 400px; margin: 0 auto; align-items: center; text-align: center;">
            <?php if (!empty($error)): ?>
                <p style="color:red;"><strong>Error:</strong> <?= e($error) ?></p>
            <?php endif; ?>
            <?php if (!empty($success)): ?>
                <p style="color:green;"><strong>Success:</strong> <?= e($success) ?></p>
            <?php endif; ?>
            <?php if (isset($_GET['verify'])): ?>
                <h1>Verify Your Email</h1>
                <p>A verification code has been sent to <strong><?= e($_SESSION['reg_email'] ?? '') ?></strong></p>
                <p>Please enter the 6-digit code to continue:</p>
                <div class="form-container">
                    <form method="post" action="regTutor.php?verify=1">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <input type="text" name="verification_code" class="verification-input"
                                maxlength="6" pattern="[0-9]{6}" placeholder="000000" required>
                        </div>
                        <button type="submit" name="verify">Verify Code</button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        <a href="regTutor.php">Back to Registration</a>
                        <?php if (isset($_SESSION['reg_attempts']) && $_SESSION['reg_attempts'] > 0): ?>
                            <br><small>Failed attempts: <?= $_SESSION['reg_attempts'] ?>/3</small>
                        <?php endif; ?>
                    </p>
                </div>

            <?php else: ?>
                <h1>Register New Tutor</h1>
                <div class="form-container">
                    <form method="post" action="regTutor.php">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <label for="email">Email:</label>
                            <input type="email" name="email" id="email" value="<?= e($email) ?>"
                                onfocus="this.setAttribute('placeholder', 'Enter email')"
                                onblur="this.removeAttribute('placeholder')" required>
                        </div>
                        <div>
                            <label for="userLogin">Create Username:</label>
                            <input type="text" name="userLogin" id="userLogin" value="<?= e($userLogin) ?>"
                                pattern="[a-z0-9-]{1,20}"
                                title="Username can only contain lowercase letters, numbers, and dashes. Maximum 20 characters."
                                onfocus="this.setAttribute('placeholder', 'Only a-z, 1-0, and -, max 20 characters')"
                                onblur="this.removeAttribute('placeholder')" required>
                        </div>
                        <div>
                            <label for="userPassword">Create Password:</label>
                            <input type="password" name="userPassword" id="userPassword"
                                onfocus="this.setAttribute('placeholder', 'Enter password')"
                                onblur="this.removeAttribute('placeholder')" required>
                        </div>
                        <div>
                            <label for="userPasswordConfirm">Confirm Password:</label>
                            <input type="password" name="userPasswordConfirm" id="userPasswordConfirm"
                                onfocus="this.setAttribute('placeholder', 'Re-enter password')"
                                onblur="this.removeAttribute('placeholder')" required>
                        </div>
                        <button type="submit" name="register">Register</button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        Already have an account? <a href="editTutor.php">Login here</a>
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