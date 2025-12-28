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
    die("Connection failed: " . $dbc->connect_error);
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
    $stmt = $dbc->prepare("SELECT * FROM UILanguage WHERE lang = 'en' LIMIT 1");
    $stmt->execute();
    $result = $stmt->get_result();
    $lang = $result->fetch_assoc();
}
$stmt->close();

function e($str)
{
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
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

function getPlatformDisplayName($platform)
{
    $names = [
        'youtube' => 'YouTube',
        'facebook' => 'Facebook',
        'line' => 'Line',
        'instagram' => 'Instagram',
        'whatsApp' => 'WhatsApp',
        'linktree' => 'Linktree',
        'email' => 'Email'
    ];
    return $names[$platform] ?? ucfirst($platform);
}

// Example data
$tutorData = [
    'key' => 'example',
    'name' => 'Example Tutor',
    'contact' => 'email',
    'URL' => 'nico@brunotutor.com',
    'contact2' => 'youtube',
    'URL2' => 'youtube',
    'contact3' => 'instagram',
    'URL3' => 'instagram',
    'header' => $lang['about'],
    'about' => $lang['content'] . '...',
    'header2' => $lang['lesson'],
    'lessons' => $lang['content'] . '...',
    'video' => '',
    'header3' => $lang['booking'],
    'booking' => $lang['content'] . '...',
    'lesson1' => $lang['lessonTitle'] . ' 1',
    'lesson1Duration' => $lang['duration'],
    'lesson1Cost' => $lang['cost'],
    'lesson1Place' => $lang['place'],
    'lesson2' => $lang['lessonTitle'] . ' 2',
    'lesson2Duration' => $lang['duration'],
    'lesson2Cost' => $lang['cost'],
    'lesson2Place' => $lang['place'],
    'lesson3' => $lang['lessonTitle'] . ' 3',
    'lesson3Duration' => $lang['duration'],
    'lesson3Cost' => $lang['cost'],
    'lesson3Place' => $lang['place'],
    'calUser' => 'exampleuser'
];
?>
<!doctype html>
<html>

<head>
    <title>BrunoTutor.com - <?= e($lang['example']); ?></title>
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
                        <a href="home.png" target="_blank">
                            <img src="home.png" title="example">
                        </a>
                        <div>
                            <h1 style="margin-top: 0;"><?= htmlspecialchars($tutorData['name']); ?></h1>
                            <p style="margin-top: 0; margin-left: 5px;">
                                <a href="mailto:<?= htmlspecialchars($tutorData['URL']); ?>" target="_blank"><?= htmlspecialchars(getPlatformDisplayName($tutorData['contact'])); ?></a>
                                &nbsp;&nbsp;<a href="https://youtube.com/<?= htmlspecialchars($tutorData['URL2']); ?>" target="_blank"><?= htmlspecialchars(getPlatformDisplayName($tutorData['contact2'])); ?></a>
                                &nbsp;&nbsp;<a href="https://instagram.com/<?= htmlspecialchars($tutorData['URL3']); ?>" target="_blank"><?= htmlspecialchars(getPlatformDisplayName($tutorData['contact3'])); ?></a>
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row" style="margin-top: 1.5rem;">
                <div class="col">
                    <h2><?= e($tutorData['header']); ?></h2>

                    <div class="content-section">
                        Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam convallis dui eget velit volutpat viverra. Nulla egestas efficitur sollicitudin.
                        <br><br>Aliquam sit amet sapien et neque sollicitudin commodo. Duis erat dui, egestas vel lectus a, semper pellentesque dolor. Praesent eu malesuada lectus. Phasellus tincidunt ut ante congue pellentesque. Ut blandit efficitur accumsan. In augue justo, congue et leo eu, sollicitudin eleifend nisi. Nunc varius purus id eros placerat, in laoreet nisi varius. Morbi congue, metus in maximus laoreet, eros turpis mollis nunc, non volutpat libero est sed quam.
                        <br><br> Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam convallis dui eget velit volutpat viverra. Nulla egestas efficitur sollicitudin. Aliquam sit amet sapien et neque sollicitudin commodo. Morbi congue, metus in maximus laoreet, eros turpis mollis nunc, non volutpat libero est sed quam.
                    </div>
                </div>
                <div class="col">
                    <h2><?= e($tutorData['header2']); ?></h2>
                    <div class="content-section">
                        Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam convallis dui eget velit volutpat viverra. Nulla egestas efficitur sollicitudin. Aliquam sit amet sapien et neque sollicitudin commodo.
                    </div><br>
                    <iframe width="100%" height="315" src="https://www.youtube.com/embed/y8Kyi0WNg40?si=ZbMS33BlYdqLoK26" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

                </div>
            </div>

            <div style="text-align: center; margin-top: 1.5rem;">
                <h2><?= e($tutorData['header3']); ?></h2>
                <div class="content-section">
                    <?= nl2p($tutorData['booking']); ?>
                </div>
            </div>

            <div class="buttons-container">
                <?php for ($i = 1; $i <= 3; $i++): ?>
                    <?php if (!empty($tutorData["lesson{$i}"])): ?>
                        <a href="#lesson<?= $i ?>" class="chunky-button"
                            data-cal-link="<?= e($tutorData["calUser"]) ?>/<?= $i ?>"
                            data-cal-namespace="<?= $i ?>"
                            data-cal-config='{"layout":"month_view"}'>
                            <h2><?= e($tutorData["lesson{$i}"]); ?></h2>
                            <div class="button-content">
                                <div class="info-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M16.24 7.75A5.974 5.974 0 0 0 12 5.99v6l-4.24 4.24c2.34 2.34 6.14 2.34 8.49 0a5.99 5.99 0 0 0-.01-8.48zM12 1.99c-5.52 0-10 4.48-10 10s4.48 10 10 10 10-4.48 10-10-4.48-10-10-10zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8z"></path>
                                    </svg>
                                    <span><?= e($tutorData["lesson{$i}Duration"]); ?></span>
                                </div>
                                <div class="info-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"></path>
                                    </svg>
                                    <span><?= e($tutorData["lesson{$i}Cost"]); ?></span>
                                </div>
                                <div class="info-row">
                                    <svg focusable="false" viewBox="0 0 24 24">
                                        <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                    </svg>
                                    <span><?= e($tutorData["lesson{$i}Place"]); ?></span>
                                </div>
                            </div>
                        </a>
                    <?php endif; ?>
                <?php endfor; ?>
            </div>
        </div>
    </main>

    <footer class="footer">
        <small><a href="index.php">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
        <small><a href="regTutor.php"><?= e($lang['createPage']); ?></a> • <a href="tos.php"><?= e($lang['terms']); ?></a></small>
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