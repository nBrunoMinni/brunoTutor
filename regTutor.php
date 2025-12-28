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
            $_SESSION['lang'] = 'en';
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

function sendVerificationEmail($email, $code, $lang)
{
    $to = $email;
    $subject = "BrunoTutor " . $lang['emailVerification'];
    $message = "
    <html>
    <head>
        <title>" . htmlspecialchars($lang['emailVerification'], ENT_QUOTES, 'UTF-8') . "</title>
    </head>
    <body>
        <p>" . htmlspecialchars($lang['thankReg'], ENT_QUOTES, 'UTF-8') . "</p>
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

$userLogin = $email = "";
$error = "";

// STEP 1: Initial registration form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = $lang['securityFail'];
    } else {
        $userLogin = $_POST['userLogin'] ?? '';
        $plainPass = $_POST['userPassword'] ?? '';
        $confirmPass = $_POST['userPasswordConfirm'] ?? '';
        $email = $_POST['email'] ?? '';

        if (empty($userLogin) || empty($plainPass) || empty($confirmPass) || empty($email)) {
            $error = $lang['required'];
        } elseif ($plainPass !== $confirmPass) {
            $error = $lang['passwordMatch'];
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = $lang['emailValid'];
        } elseif (strlen($userLogin) > 20 || !preg_match('/^[a-z0-9-]+$/', $userLogin)) {
            $error = $lang['usernameRules'];
        } else {
            // If username exists
            $stmtCheck = $dbc->prepare("SELECT 1 FROM bruno WHERE userLogin = ? LIMIT 1");
            $stmtCheck->bind_param("s", $userLogin);
            $stmtCheck->execute();
            $resCheck = $stmtCheck->get_result();
            if ($resCheck && $resCheck->num_rows > 0) {
                $error = $lang['userTaken'];
            }
            $stmtCheck->close();

            $stmtCheckTemp = $dbc->prepare("SELECT 1 FROM brunoTemp WHERE userLogin = ? LIMIT 1");
            $stmtCheckTemp->bind_param("s", $userLogin);
            $stmtCheckTemp->execute();
            $resCheckTemp = $stmtCheckTemp->get_result();
            if ($resCheckTemp && $resCheckTemp->num_rows > 0) {
                $error = $lang['userTaken'];
            }
            $stmtCheckTemp->close();

            // If email exists
            $stmtCheckEmailTemp = $dbc->prepare("SELECT 1 FROM bruno WHERE email = ? LIMIT 1");
            $stmtCheckEmailTemp->bind_param("s", $email);
            $stmtCheckEmailTemp->execute();
            $resCheckEmailTemp = $stmtCheckEmailTemp->get_result();
            if ($resCheckEmailTemp && $resCheckEmailTemp->num_rows > 0) {
                $error = $lang['emailTaken'];
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

            $emailSent = sendVerificationEmail($email, $verificationCode, $lang);

            if ($emailSent) {
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                header("Location: regTutor.php?verify=1");
                exit;
            } else {
                $error = $lang['failedToSend'];
            }
        }
    }
}

// STEP 2: Verify email with code
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = $lang['securityFail'];
    } else {
        $enteredCode = $_POST['verification_code'] ?? '';

        if (!isset($_SESSION['reg_code']) || !isset($_SESSION['reg_expiry'])) {
            $error = $lang['verificationFail'];
        } elseif (time() > $_SESSION['reg_expiry']) {
            $error = $lang['verificationFail'];
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
                $error = $lang['verificationFail'];
                unset($_SESSION['reg_code']);
                unset($_SESSION['reg_expiry']);
                unset($_SESSION['reg_attempts']);
            } else {
                $remainingAttempts = 3 - $_SESSION['reg_attempts'];
                $error = $lang['invalid'] . " {$remainingAttempts} " . $lang['attempts'];
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
    <title>BrunoTutor.com - <?= e($lang['register']); ?></title>
    <link href="style.css" rel="stylesheet">
    <link href="logStyle.css" rel="stylesheet">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/x-icon" href="home.ico">
</head>

<body>
    <main class="main">
        <div class="container" style="max-width: 400px; margin: 0 auto; align-items: center; text-align: center;">
            <?php if (!empty($error)): ?>
                <p style="color:red;"><strong><?= e($lang['error']); ?></strong> <?= e($error) ?></p>
            <?php endif; ?>
            <?php if (!empty($success)): ?>
                <p style="color:green;"><strong><?= e($lang['success']); ?></strong> <?= e($success) ?></p>
            <?php endif; ?>

            <?php if (isset($_GET['verify'])): ?>
                <h1><?= e($lang['verify']); ?></h1>
                <p><?= e($lang['verificationSent']); ?> <strong><?= e($_SESSION['reg_email'] ?? '') ?></strong></p>
                <p><?= e($lang['pleaseEnter']); ?></p>
                <div class="form-container">
                    <form method="post" action="regTutor.php?verify=1">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <input type="text" name="verification_code" class="verification-input"
                                maxlength="6" pattern="[0-9]{6}" placeholder="000000" required>
                        </div>
                        <button type="submit" name="verify"><?= e($lang['verify']); ?></button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        <a href="regTutor.php"><?= e($lang['register']); ?></a>
                        <?php if (isset($_SESSION['reg_attempts']) && $_SESSION['reg_attempts'] > 0): ?>
                            <br><small><?= e($lang['failedAttempts']); ?> <?= $_SESSION['reg_attempts'] ?>/3</small>
                        <?php endif; ?>
                    </p>
                </div>

            <?php else: ?>
                <h1><?= e($lang['register']); ?></h1>
                <div class="form-container">
                    <form method="post" action="regTutor.php">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <label for="email"><?= e($lang['email']); ?></label>
                            <input type="email" name="email" id="email" value="<?= e($email) ?>" required>
                        </div>
                        <div>
                            <label for="userLogin"><?= e($lang['username']); ?></label>
                            <input type="text" name="userLogin" id="userLogin" value="<?= e($userLogin) ?>"
                                pattern="[a-z0-9-]{1,20}"
                                title="<?= e($lang['usernameRules']); ?>" required>
                        </div>
                        <div>
                            <label for="userPassword"><?= e($lang['password']); ?></label>
                            <input type="password" name="userPassword" id="userPassword" required>
                        </div>
                        <div>
                            <label for="userPasswordConfirm"><?= e($lang['confirmPassword']); ?></label>
                            <input type="password" name="userPasswordConfirm" id="userPasswordConfirm" required>
                        </div>
                        <button type="submit" name="register"><?= e($lang['register']); ?></button>
                    </form>
                    <p style="text-align: center; margin-top: 20px;">
                        <?= e($lang['already']); ?> <a href="editTutor.php"><?= e($lang['login']); ?></a>
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