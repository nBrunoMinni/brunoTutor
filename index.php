<?php
$host = "localhost";
$username = "interalp_brunoDB";
$password = "jfjOjhfqqhlfi*#**0nj1";
$database = "interalp_brunoDB";

$dbc = new mysqli($host, $username, $password, $database);
$user = 'user';
$query = "SELECT * FROM bruno";
$rows = $dbc->query($query)->fetch_all(MYSQLI_ASSOC);
$keyedRows = [];
foreach ($rows as $row) {
    foreach ($row as $columnName => $value) {
        if ($columnName !== 'key') {
            $keyedRows[$columnName][$row['key']] = $value;
        }
    }
}
?>
<!doctype html>
<html>
<head>
    <title>BrunoTutor.com</title>
    <meta charset='utf-8' />
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/x-icon" href="home.ico">
    <link href="style.css" rel="stylesheet">
</head>
<body>
    <main class="main">
        <div class="container">
            <div class="row">
                <div class="col">
                    <div class="inline-content">
                        <a href="home.png" target="_blank">
                            <img src="home.png" title="home">
                        </a>
                        <div>
                            <h1 style="margin-top: 0;"><?= $keyedRows['name']['home']; ?></h1>
                            <p style="margin-top: 0;"><?= $keyedRows['contact']['home']; ?></p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col">
                    <h2>About</h2>
                    <p dir="auto">
                    <p>
                        <?= $keyedRows['about']['home']; ?>
                    </p>
                </div>
                <div class="col">
                    <h2>Tutor on BrunoTutor</h2>
                    <p>
                        <?= $keyedRows['lessons']['home']; ?>
                    </p>
                </div>
            </div>
            <br>
            <div style="text-align: center; margin-bottom: 10px;">
                <h2>Tutors</h2>
                <p><?= $keyedRows['booking']['home']; ?></p>
            </div>
            <div class="buttons-container">
                <?php foreach ($keyedRows['name'] as $colName => $nameValue) :
                    if (in_array($colName, ['key', 'home', 'example'])) {
                        continue;
                    }
                    $placeValue = $keyedRows['place'][$colName] ?? 'Unknown'; 
                    $tagsString = $keyedRows['tags'][$colName] ?? ''; 
                    preg_match_all('/\b\w+\b/', $tagsString, $matches);
                    $badges = array_map(function ($tag) {
                        return "<span class='badge'>$tag</span>";
                    }, $matches[0]);
                     ?>
                    <a href="https://brunotutor.com/<?= urlencode($colName); ?>" class="chunky-button">
                        <div class="inline-content">
                            <img src="<?= htmlspecialchars($colName); ?>.png" title="tutor pic">
                            <div>
                                <h2><?= htmlspecialchars($nameValue); ?></h2>
                                <div class="button-content">
                                    <div class="info-row">
                                        <svg focusable="false" viewBox="0 0 24 24" width="20" height="20">
                                            <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5S10.62 6.5 12 6.5s2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"></path>
                                        </svg>
                                        <span><?= htmlspecialchars($placeValue); ?></span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div style="
                            margin-top: 10px;
                            justify-content: center;
                            align-items: center;
                            text-align: center;">
                            <div class="badge-wrapper">
                                <?= implode(" ", $badges); ?>
                            </div>
                        </div>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>
    </main>
    <footer class="footer">
        <small><a href="https://www.brunotutor.com">BrunoTutor.com</a> &copy; <?php echo date("Y"); ?></small><br>
    </footer>
</body>
</html>