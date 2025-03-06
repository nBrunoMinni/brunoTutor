<?php
$host = "localhost";
$username = "interalp_brunoDB";
$password = "jfjOjhfqqhlfi*#**0nj1";
$database = "interalp_brunoDB";

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
// If no matching tutor, redirect home
if (!array_key_exists($pageFile, $tutors)) {
    header("Location: /");
    exit;
}
// Fetch tutor data
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
</head>
<body>
    <main class="main">
        <div class="container">
            <div class="row">
                <div class="col">
                    <div class="inline-content">
                        <a href="<?= htmlspecialchars($pageFile) ?>.png" target="_blank">
                            <img src="<?= htmlspecialchars($pageFile) ?>.png" title="<?= htmlspecialchars($pageFile) ?>">
                        </a>
                        <div>
                            <h1 class="text-center"><?= htmlspecialchars($tutorData['name']); ?></h1>
                            <p class="text-center"><?= $tutorData['contact'] ?? "No contact available."; ?></p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col">
                    <h2>About Me</h2>
                    <p><?= $tutorData['about'] ?? "No bio information available."; ?></p>
                </div>
                <div class="col">
                    <h2>Lessons</h2>
                    <p><?= $tutorData['lessons'] ?? "No lesson information available."; ?></p>
                </div>
            </div>
            <div style="text-align: center;">
                <h2>Booking</h2>
                <p><?= $tutorData['booking'] ?? "No booking information available."; ?></p>
            </div>
            <div class="buttons-container">
                <?php for ($i = 1; $i <= 3; $i++): ?>
                    <?php if (!empty($tutorData["lesson{$i}"])): ?>
                        <a href="#lesson<?= $i ?>" class="chunky-button"
                            data-cal-link="<?= $tutorData["calUser"] ?? "" ?>/<?= $i ?>"
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
    </footer>
    <!-- Cal dot com popovers -->
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