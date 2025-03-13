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

function nl2p($text)
{
    $text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    $text = preg_replace('/\*\*(.*?)\*\*/s', '<strong>$1</strong>', $text);
    $text = preg_replace('/(?<!\*)\*(?!\*)(.*?)(?<!\*)\*(?!\*)/s', '<em>$1</em>', $text);

    $text = str_replace(["\r\n", "\r"], "\n", $text);
    $paragraphs = preg_split('/\n{2,}/', $text);
    $paragraphs = array_map('trim', $paragraphs);
    $paragraphs = array_filter($paragraphs);
    $paragraphs = array_map(function ($p) {
        return str_replace("\n", '<br>', $p);
    }, $paragraphs);
    return '<p>' . implode('</p><p>', $paragraphs) . '</p>';
}

$dbc = new mysqli($host, $username, $password, $database);
if ($dbc->connect_error) {
    die("Connection failed: " . $dbc->connect_error);
}
$query = "SELECT * FROM bruno";
$result = $dbc->query($query);
if (!$result) {
    die("Query failed: " . $dbc->error);
}
$rows = $result->fetch_all(MYSQLI_ASSOC);
$tutors = [];
foreach ($rows as $row) {
    $tutorKey = strtolower(trim($row['key']));
    $tutors[$tutorKey] = $row;
}
$pageFile = isset($_GET['name']) ? strtolower(trim($_GET['name'])) : "";
if (!array_key_exists($pageFile, $tutors)) {
    header("Location: /");
    exit;
}
$tutorData = $tutors[$pageFile];
?>
<!doctype html>
<html>

<head>
    <title>BrunoTutor.com - <?= htmlspecialchars($tutorData['name']); ?></title>
    <meta charset='utf-8' />
    <link href="style.css" rel="stylesheet">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/x-icon" href="home.ico">
    <style>
        .content-section p {
            margin-bottom: 1em;
        }

        .content-section p:last-child {
            margin-bottom: 0;
        }
    </style>
</head>

<body>
    <main class="main">
        <div class="container">
            <div class="row">
                <div class="col">
                    <div class="inline-content">
                        <a href="uploads/<?= htmlspecialchars($tutorData['key']); ?>.png" target="_blank">
                            <img src="uploads/<?= htmlspecialchars($tutorData['key']); ?>.png" title="<?= htmlspecialchars($tutorData['key']); ?>">
                        </a>
                        <div>
                            <h1 class="text-center"><?= htmlspecialchars($tutorData['name']); ?></h1>
                            <p class="text-center">
                                <?php if (!empty($tutorData['URL'])): ?>
                                    <a href="<?= htmlspecialchars($tutorData['URL']); ?>" target="_blank"><?= htmlspecialchars($tutorData['contact']); ?></a>
                                <?php else: ?>
                                    <?= htmlspecialchars($tutorData['contact']); ?>
                                <?php endif; ?>
                                &nbsp;&nbsp;
                                <?php if (!empty($tutorData['URL2'])): ?>
                                    <a href="<?= htmlspecialchars($tutorData['URL2']); ?>" target="_blank"><?= htmlspecialchars($tutorData['contact2']); ?></a>
                                <?php else: ?>
                                    <?= htmlspecialchars($tutorData['contact2']); ?>
                                <?php endif; ?>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col">
                    <h2>About Me</h2>
                    <div class="content-section">
                        <?= nl2p($tutorData['about'] ?? "No bio information available."); ?>
                    </div>
                </div>
                <div class="col">
                    <h2>Lessons</h2>
                    <div class="content-section">
                        <?= nl2p($tutorData['lessons'] ?? "No lesson information available."); ?>
                    </div>
                </div>
            </div>
            <div style="text-align: center;">
                <h2>Booking</h2>
                <div class="content-section">
                    <?= nl2p($tutorData['booking'] ?? "No booking information available."); ?>
                </div>
            </div>
            <div class="buttons-container">
                <?php for ($i = 1; $i <= 3; $i++): ?>
                    <?php if (!empty($tutorData["lesson{$i}"])): ?>
                        <a href="#lesson<?= $i ?>" class="chunky-button"
                            data-cal-link="<?= htmlspecialchars($tutorData["calUser"] ?? "") ?>/<?= $i ?>"
                            data-cal-namespace="<?= $i ?>"
                            data-cal-config='{"layout":"month_view"}'>
                            <h2><?= htmlspecialchars($tutorData["lesson{$i}"]); ?></h2>
                            <div class="button-content">
                                <div class="info-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                    </svg>
                                    <span><?= htmlspecialchars($tutorData["lesson{$i}Duration"] ?? ""); ?></span>
                                </div>
                                <div class="info-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                    </svg>
                                    <span><?= htmlspecialchars($tutorData["lesson{$i}Cost"] ?? ""); ?></span>
                                </div>
                                <div class="info-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                    </svg>
                                    <span><?= htmlspecialchars($tutorData["lesson{$i}Place"] ?? ""); ?></span>
                                </div>
                            </div>
                        </a>
                    <?php endif; ?>
                <?php endfor; ?>
            </div>
        </div>
    </main>

    <footer class="footer">
        <small><a href="https://www.brunotutor.com">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
        <small><a href="https://www.brunotutor.com/regTutor.php">Create page</a> • <a href="https://www.brunotutor.com/tos.php">Terms of service</a></small>
    </footer>
    <script type="text/javascript">
        (function(C, A, L) {
            let p = function(a, ar) {
                a.q.push(ar);
            };
            let d = C.document;
            C.Cal = C.Cal || function() {
                let cal = C.Cal;
                let ar = arguments;
                if (!cal.loaded) {
                    cal.ns = {};
                    cal.q = cal.q || [];
                    d.head.appendChild(d.createElement("script")).src = A;
                    cal.loaded = true;
                }
                if (ar[0] === L) {
                    const api = function() {
                        p(api, arguments);
                    };
                    const namespace = ar[1];
                    api.q = api.q || [];
                    if (typeof namespace === "string") {
                        cal.ns[namespace] = cal.ns[namespace] || api;
                        p(cal.ns[namespace], ar);
                        p(cal, ["initNamespace", namespace]);
                    } else p(cal, ar);
                    return;
                }
                p(cal, ar);
            };
        })(window, "https://app.cal.com/embed/embed.js", "init");
        Cal("init", "3", {
            origin: "https://cal.com"
        });
        Cal.ns["3"]("ui", {
            "hideEventTypeDetails": false,
            "layout": "month_view"
        });
    </script>
    <script type="text/javascript">
        (function(C, A, L) {
            let p = function(a, ar) {
                a.q.push(ar);
            };
            let d = C.document;
            C.Cal = C.Cal || function() {
                let cal = C.Cal;
                let ar = arguments;
                if (!cal.loaded) {
                    cal.ns = {};
                    cal.q = cal.q || [];
                    d.head.appendChild(d.createElement("script")).src = A;
                    cal.loaded = true;
                }
                if (ar[0] === L) {
                    const api = function() {
                        p(api, arguments);
                    };
                    const namespace = ar[1];
                    api.q = api.q || [];
                    if (typeof namespace === "string") {
                        cal.ns[namespace] = cal.ns[namespace] || api;
                        p(cal.ns[namespace], ar);
                        p(cal, ["initNamespace", namespace]);
                    } else p(cal, ar);
                    return;
                }
                p(cal, ar);
            };
        })(window, "https://app.cal.com/embed/embed.js", "init");
        Cal("init", "2", {
            origin: "https://cal.com"
        });
        Cal.ns["2"]("ui", {
            "hideEventTypeDetails": false,
            "layout": "month_view"
        });
    </script>
    <script type="text/javascript">
        (function(C, A, L) {
            let p = function(a, ar) {
                a.q.push(ar);
            };
            let d = C.document;
            C.Cal = C.Cal || function() {
                let cal = C.Cal;
                let ar = arguments;
                if (!cal.loaded) {
                    cal.ns = {};
                    cal.q = cal.q || [];
                    d.head.appendChild(d.createElement("script")).src = A;
                    cal.loaded = true;
                }
                if (ar[0] === L) {
                    const api = function() {
                        p(api, arguments);
                    };
                    const namespace = ar[1];
                    api.q = api.q || [];
                    if (typeof namespace === "string") {
                        cal.ns[namespace] = cal.ns[namespace] || api;
                        p(cal.ns[namespace], ar);
                        p(cal, ["initNamespace", namespace]);
                    } else p(cal, ar);
                    return;
                }
                p(cal, ar);
            };
        })(window, "https://app.cal.com/embed/embed.js", "init");
        Cal("init", "1", {
            origin: "https://cal.com"
        });
        Cal.ns["1"]("ui", {
            "hideEventTypeDetails": false,
            "layout": "month_view"
        });
    </script>
</body>
</html>