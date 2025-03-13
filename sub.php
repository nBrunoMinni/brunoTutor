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
    die("Database connection failed: " . $dbc->connect_error);
}

// HTML escaping, should apply this everywhere
function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

function sendApprovalEmail($email, $name, $key)
{
    $to = $email;
    $subject = "BrunoTutor Profile Approved";
    $message = "
    <html>
    <head>
        <title>Profile Approved</title>
    </head>
    <body>
        <p>Congratulations " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!</p>
    <p>Your tutor profile has been approved and is now live at <a href='https://brunotutor.com/" . htmlspecialchars($key, ENT_QUOTES, 'UTF-8') . "'>BrunoTutor.com/" . htmlspecialchars($key, ENT_QUOTES, 'UTF-8') . "</a>.</p>
    <p>You can now login to edit your profile at <a href='https://brunotutor.com/editTutor.php'>BrunoTutor.com/editTutor.php</a>.</p>
</body>
    </html>
    ";
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= 'From: no-reply@brunotutor.com' . "\r\n";

    return mail($to, $subject, $message, $headers);
}

function sendChangesNeededEmail($email, $name, $notes, $tutorData)
{
    $to = $email;
    $subject = "BrunoTutor Profile Needs Changes";
    $profileData = "
    <h3>Your Current Profile Data:</h3>
    <table style='border-collapse: collapse; width: 100%;'>
      <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Username:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['key']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Name:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['name']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Email:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['email']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Contact 1:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['contact']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Link 1:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['URL']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Contact 2:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['contact2']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Link 2:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['URL2']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>About:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . nl2br(e($tutorData['about'])) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lessons:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . nl2br(e($tutorData['lessons'])) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Booking:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . nl2br(e($tutorData['booking'])) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 1:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson1']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 1 Duration:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson1Duration']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 1 Cost:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson1Cost']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 1 Place:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson1Place']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 2:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson2']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 2 Duration:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson2Duration']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 2 Cost:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson2Cost']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 2 Place:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson2Place']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 3:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson3']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 3 Duration:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson3Duration']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 3 Cost:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson3Cost']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Lesson 3 Place:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['lesson3Place']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Cal.com Username:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['calUser']) . "</td>
        </tr>
        <tr>
            <td style='padding: 8px; border: 1px solid #ddd;'><strong>Tags:</strong></td>
            <td style='padding: 8px; border: 1px solid #ddd;'>" . e($tutorData['tags']) . "</td>
        </tr>
    </table>";
    $message = "
    <html>
    <head>
        <title>Profile Changes Requested</title>
    </head>
    <body>
        <p>Hello {$name},</p>
        <p>Thank you for submitting your tutor profile to BrunoTutor.</p>
        <p>We've reviewed your submission and need you to make some changes before we can approve it:</p>
        <div style='background-color: #f5f5f5; padding: 10px; border-left: 4px solid #ccc; margin: 10px 0;'>
            " . nl2br(e($notes)) . "
        </div>
        
        " . $profileData . "
        
        <p>Please submit a new application with these changes.</p>
    </body>
    </html>
    ";
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= 'From: no-reply@brunotutor.com' . "\r\n";

    return mail($to, $subject, $message, $headers);
}

$requestedTutor = isset($_GET['name']) ? $_GET['name'] : '';
$isAdmin = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
if (isset($_POST['admin_login'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $loginError = "Security validation failed. Please try again.";
    } else {
        $adminUser = $_POST['admin_username'] ?? '';
        $adminPass = $_POST['admin_password'] ?? '';
        if ($adminUser === 'adminUser') {
            $stmt = $dbc->prepare("SELECT userHash FROM adminTable WHERE userLogin = ? LIMIT 1");
            $stmt->bind_param('s', $adminUser);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows === 1) {
                $row = $result->fetch_assoc();
                $hashedPassword = $row['userHash'];
                if (password_verify($adminPass, $hashedPassword)) {
                    $_SESSION['admin_logged_in'] = true;
                    $isAdmin = true;
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                } else {
                    $loginError = "Invalid admin credentials";
                }
            } else {
                $loginError = "Admin account not found";
            }
            $stmt->close();
        } else {
            $loginError = "Invalid admin credentials";
        }
    }
}

if ($isAdmin && isset($_POST['admin_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $actionError = "Security validation failed. Please try again.";
    } else {
        $tutorLogin = $_POST['tutor_login'] ?? '';
        $adminNotes = $_POST['admin_notes'] ?? '';

        if ($_POST['admin_action'] === 'approve') {
            $stmt = $dbc->prepare("SELECT * FROM brunoTemp WHERE userLogin = ? LIMIT 1");
            $stmt->bind_param("s", $tutorLogin);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows === 1) {
                $tutorData = $result->fetch_assoc();
                $checkStmt = $dbc->prepare("SELECT 1 FROM bruno WHERE userLogin = ? LIMIT 1");
                $checkStmt->bind_param("s", $tutorLogin);
                $checkStmt->execute();
                $checkResult = $checkStmt->get_result();
                if ($checkResult && $checkResult->num_rows > 0) {
                    $actionError = "A tutor with this username already exists in the main database.";
                } else {
                    if (!isset($tutorData['key'])) {
                        $tutorData['key'] = $tutorData['userLogin'];
                    }
                    $insertSQL = "INSERT INTO bruno (";
                    $valueSQL = " VALUES (";
                    $types = "";
                    $values = [];

                    foreach ($tutorData as $column => $value) {
                        if ($column !== 'id' && $column !== 'submitted_date') {
                            // Escape column names for 'key' (why did I do this omg)
                            $insertSQL .= "`{$column}`, ";
                            $valueSQL .= "?, ";
                            $types .= "s"; // Fields as strings
                            $values[] = $value;
                        }
                    }

                    $insertSQL = rtrim($insertSQL, ", ") . ")";
                    $valueSQL = rtrim($valueSQL, ", ") . ")";
                    $finalSQL = $insertSQL . $valueSQL;
                    $insertStmt = $dbc->prepare($finalSQL);
                    if ($insertStmt) {
                        $params = array($types);
                        foreach ($values as $key => $value) {
                            $params[] = &$values[$key];
                        }
                        call_user_func_array(array($insertStmt, 'bind_param'), $params);
                        if ($insertStmt->execute()) {
                            $deleteStmt = $dbc->prepare("DELETE FROM brunoTemp WHERE userLogin = ?");
                            $deleteStmt->bind_param("s", $tutorLogin);
                            $deleteStmt->execute();
                            $deleteStmt->close();
                            sendApprovalEmail($tutorData['email'], $tutorData['name'], $tutorData['key']);
                            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                            $actionSuccess = "Tutor profile has been approved and moved to the main database.";
                        } else {
                            $actionError = "Error approving tutor: " . $insertStmt->error;
                        }
                        $insertStmt->close();
                    } else {
                        $actionError = "Error preparing SQL statement: " . $dbc->error;
                    }
                }
                $checkStmt->close();
            }
            $stmt->close();
        } elseif ($_POST['admin_action'] === 'changes') {
            $stmt = $dbc->prepare("SELECT * FROM brunoTemp WHERE userLogin = ? LIMIT 1");
            $stmt->bind_param("s", $tutorLogin);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result && $result->num_rows === 1) {
                $tutorData = $result->fetch_assoc();
                if (sendChangesNeededEmail($tutorData['email'], $tutorData['name'], $adminNotes, $tutorData)) {
                    $deleteStmt = $dbc->prepare("DELETE FROM brunoTemp WHERE userLogin = ?");
                    $deleteStmt->bind_param("s", $tutorLogin);
                    $deleteStmt->execute();
                    $deleteStmt->close();
                    $actionSuccess = "Changes requested email has been sent to the tutor.";
                } else {
                    $actionError = "Error sending changes needed email.";
                }
            }
            $stmt->close();
        }
    }
}

$tutorData = null;
if ($isAdmin && !empty($requestedTutor)) {
    $stmt = $dbc->prepare("SELECT * FROM brunoTemp WHERE userLogin = ? LIMIT 1");
    $stmt->bind_param("s", $requestedTutor);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows === 1) {
        $tutorData = $result->fetch_assoc();
    } else {
        $fetchError = "No pending submission found for this tutor.";
    }
    $stmt->close();
}
if (!$isAdmin):
?>
    <!doctype html>
    <html>

    <head>
        <title>Admin Login - BrunoTutor</title>
        <meta charset="utf-8" />
        <link href="style.css" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="icon" type="image/x-icon" href="home.ico">
        <style>
            .login-container {
                max-width: 400px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f9f9f9;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            }

            .form-group {
                margin-bottom: 15px;
            }

            .form-group label {
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
            }

            .form-group input {
                width: 100%;
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                box-sizing: border-box;
            }

            .btn-primary {
                background-color: #ADDFB3;
                border: none;
                color: #333;
                padding: 10px 15px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
                width: 100%;
            }

            .btn-primary:hover {
                background-color: #9AD0A0;
            }

            .error-message {
                color: red;
                margin-bottom: 15px;
            }
        </style>
    </head>

    <body>
        <main class="main">
            <div class="login-container">
                <h1 style="text-align: center;">Admin Login</h1>

                <?php if (isset($loginError)): ?>
                    <div class="error-message">
                        <?= e($loginError) ?>
                    </div>
                <?php endif; ?>

                <form method="post" action="<?= "sub.php" . (!empty($requestedTutor) ? "?name=" . urlencode($requestedTutor) : "") ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                    <div class="form-group">
                        <label for="admin_username">Username:</label>
                        <input type="text" id="admin_username" name="admin_username" required>
                    </div>

                    <div class="form-group">
                        <label for="admin_password">Password:</label>
                        <input type="password" id="admin_password" name="admin_password" required>
                    </div>

                    <button type="submit" name="admin_login" class="btn-primary">Login</button>
                </form>
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

// If no tutor data found but admin is logged in
if ($isAdmin && !$tutorData && empty($actionSuccess)):
?>
    <!doctype html>
    <html>

    <head>
        <title>No Submission Found - BrunoTutor</title>
        <meta charset="utf-8" />
        <link href="style.css" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <link rel="icon" type="image/x-icon" href="home.ico">
        <style>
            .message-container {
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f9f9f9;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                text-align: center;
            }

            .btn {
                display: inline-block;
                margin-top: 20px;
                padding: 10px 15px;
                background-color: #ADDFB3;
                color: #333;
                text-decoration: none;
                border-radius: 4px;
                font-weight: bold;
            }
        </style>
    </head>

    <body>
        <main class="main">
            <div class="message-container">
                <h1>No Submission Found</h1>

                <?php if (isset($fetchError)): ?>
                    <p><?= e($fetchError) ?></p>
                <?php else: ?>
                    <p>No tutor submission was specified or the submission has already been processed.</p>
                <?php endif; ?>

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

// If action was successful, show success message
if ($isAdmin && isset($actionSuccess)):
?>
    <!doctype html>
    <html>

    <head>
        <title>Action Successful - BrunoTutor</title>
        <meta charset="utf-8" />
        <link href="style.css" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <link rel="icon" type="image/x-icon" href="home.ico">
        <style>
            .success-container {
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f9f9f9;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                text-align: center;
            }

            .success-icon {
                font-size: 64px;
                color: #4CAF50;
                margin-bottom: 20px;
            }

            .btn {
                display: inline-block;
                margin-top: 20px;
                padding: 10px 15px;
                background-color: #ADDFB3;
                color: #333;
                text-decoration: none;
                border-radius: 4px;
                font-weight: bold;
            }
        </style>
    </head>

    <body>
        <main class="main">
            <div class="success-container">
                <div class="success-icon">✓</div>
                <h1>Action Completed Successfully</h1>
                <p><?= e($actionSuccess) ?></p>
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

// Only gets here if admin is logged in and tutor data was found
// Extract fields for display
$userLogin     = $tutorData['userLogin']       ?? '';
$email         = $tutorData['email']           ?? '';
$name          = $tutorData['name']            ?? '';
$contact       = $tutorData['contact']         ?? '';
$URL           = $tutorData['URL']             ?? '';
$contact2      = $tutorData['contact2']        ?? '';
$URL2          = $tutorData['URL2']            ?? '';
$about         = $tutorData['about']           ?? '';
$lessons       = $tutorData['lessons']         ?? '';
$booking       = $tutorData['booking']         ?? '';
$lesson1       = $tutorData['lesson1']         ?? '';
$lesson1Dur    = $tutorData['lesson1Duration'] ?? '';
$lesson1Cost   = $tutorData['lesson1Cost']     ?? '';
$lesson1Place  = $tutorData['lesson1Place']    ?? '';
$lesson2       = $tutorData['lesson2']         ?? '';
$lesson2Dur    = $tutorData['lesson2Duration'] ?? '';
$lesson2Cost   = $tutorData['lesson2Cost']     ?? '';
$lesson2Place  = $tutorData['lesson2Place']    ?? '';
$lesson3       = $tutorData['lesson3']         ?? '';
$lesson3Dur    = $tutorData['lesson3Duration'] ?? '';
$lesson3Cost   = $tutorData['lesson3Cost']     ?? '';
$lesson3Place  = $tutorData['lesson3Place']    ?? '';
$calUser       = $tutorData['calUser']         ?? '';
$tags          = $tutorData['tags']            ?? '';
$submittedDate = $tutorData['submitted_date']  ?? '';
?>
<!doctype html>
<html>

<head>
    <title>Review Tutor Submission - <?= e($name) ?></title>
    <meta charset="utf-8" />
    <link href="style.css" rel="stylesheet">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <link rel="icon" type="image/x-icon" href="home.ico">
    <style>
        .admin-bar {
            background-color: #333;
            color: white;
            padding: 10px 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .admin-bar a {
            color: white;
            text-decoration: none;
        }

        .admin-review-section {
            background-color: #f9f9f9;
            padding: 20px;
            margin-top: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }

        .admin-notes {
            width: 100%;
            height: 120px;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }

        .admin-buttons {
            display: flex;
            gap: 10px;
        }

        .btn-approve {
            background-color: #ADDFB3;
            border: none;
            color: #333;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }

        .btn-changes {
            background-color: #FFD1D1;
            border: none;
            color: #333;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }

        .btn-approve:hover {
            background-color: #9AD0A0;
        }

        .btn-changes:hover {
            background-color: #FFBDBD;
        }

        .error-message {
            color: red;
            margin-bottom: 15px;
        }

        .inline-content {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .inline-content img {
            width: 150px;
            height: auto;
            border-radius: 5px;
        }

        .info-row {
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }

        .info-row svg {
            width: 20px;
            height: 20px;
            margin-right: 8px;
        }

        .text-center {
            text-align: center;
        }
    </style>
</head>

<body>
    <div class="admin-bar">
        <div>
            <strong>Admin Review:</strong> Submission by <?= e($name) ?> (<?= e($userLogin) ?>)
        </div>
        <div>
            <a href="sub.php?logout=1">Logout</a>
        </div>
    </div>

    <main class="main">
        <div class="container">
            <?php if (isset($actionError)): ?>
                <div class="error-message">
                    <?= e($actionError) ?>
                </div>
            <?php endif; ?>

            <div class="row">
                <div class="col">
                    <div class="inline-content">
                        <?php
                        $uploadedImage = "uploads/{$userLogin}.png";
                        if (!file_exists($uploadedImage)) {
                            $uploadedImage = "default.png";
                        }
                        ?>
                        <img src="<?= e($uploadedImage) ?>" alt="Profile Image">
                        <div>
                            <h1 class="text-center"><?= e($name) ?></h1>
                            <p class="text-center">
                                <?php if (!empty($URL)): ?>
                                    <a href="<?= e($URL); ?>" target="_blank"><?= e($contact); ?></a>
                                <?php else: ?>
                                    <?= e($contact); ?>
                                <?php endif; ?>
                                &nbsp;&nbsp;
                                <?php if (!empty($URL2)): ?>
                                    <a href="<?= e($URL2); ?>" target="_blank"><?= e($contact2); ?></a>
                                <?php else: ?>
                                    <?= e($contact2); ?>
                                <?php endif; ?>
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col">
                    <h2>About Me</h2>
                    <p><?= nl2br(e($about)) ?></p>
                </div>
                <div class="col">
                    <h2>Lessons</h2>
                    <p><?= nl2br(e($lessons)) ?></p>
                </div>
            </div>

            <div style="text-align: center;">
                <h2>Booking</h2>
                <p><?= nl2br(e($booking)) ?></p>
            </div>

            <div class="buttons-container">
                <?php if (!empty($lesson1)): ?>
                    <div class="chunky-button">
                        <h2><?= e($lesson1) ?></h2>
                        <div class="button-content">
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <span><?= e($lesson1Dur) ?></span>
                            </div>
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <span><?= e($lesson1Cost) ?></span>
                            </div>
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <span><?= e($lesson1Place) ?></span>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                <?php if (!empty($lesson2)): ?>
                    <div class="chunky-button">
                        <h2><?= e($lesson2) ?></h2>
                        <div class="button-content">
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <span><?= e($lesson2Dur) ?></span>
                            </div>
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <span><?= e($lesson2Cost) ?></span>
                            </div>
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <span><?= e($lesson2Place) ?></span>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                <?php if (!empty($lesson3)): ?>
                    <div class="chunky-button">
                        <h2><?= e($lesson3) ?></h2>
                        <div class="button-content">
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                </svg>
                                <span><?= e($lesson3Dur) ?></span>
                            </div>
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                </svg>
                                <span><?= e($lesson3Cost) ?></span>
                            </div>
                            <div class="info-row">
                                <svg focusable="false" viewBox="0 0 24 24">
                                    <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                </svg>
                                <span><?= e($lesson3Place) ?></span>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>

            <div style="margin-top: 30px; background-color: #f5f5f5; padding: 15px; border-radius: 8px;">
                <h3>Additional Information</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                    <div>
                        <p><strong>Username:</strong> <?= e($userLogin) ?></p>
                        <p><strong>Email:</strong> <?= e($email) ?></p>
                        <p><strong>Cal.com:</strong> <?= e($calUser) ?></p>
                    </div>
                    <div>
                        <p><strong>Tags:</strong> <?= e($tags) ?></p>
                        <p><strong>Submitted:</strong> <?= e($submittedDate) ?></p>
                    </div>
                </div>
            </div>

            <div class="admin-review-section">
                <h2>Admin Review</h2>
                <form method="post" action="sub.php?name=<?= urlencode($userLogin) ?>">
                    <input type="hidden" name="tutor_login" value="<?= e($userLogin) ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <div style="margin-bottom: 15px;">
                        <label for="admin_notes"><strong>Notes:</strong></label>
                        <textarea id="admin_notes" name="admin_notes" class="admin-notes" placeholder="Enter your notes or feedback here. This will be sent to the tutor if changes are needed."></textarea>
                    </div>
                    <div class="admin-buttons">
                        <button type="submit" name="admin_action" value="approve" class="btn-approve" onclick="return confirm('Are you sure you want to approve this profile?');">Approve Profile</button>
                        <button type="submit" name="admin_action" value="changes" class="btn-changes" onclick="return confirm('Are you sure you want to request changes?');">Request Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </main>
    <footer class="footer">
        <small><a href="https://www.brunotutor.com">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
        <small><a href="https://www.brunotutor.com/regTutor.php">Create page</a> • <a href="https://www.brunotutor.com/tos.php">Terms of service</a></small>
    </footer>
</body>

</html>