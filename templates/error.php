<?php if (!function_exists('e')) { http_response_code(404); exit; } ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Campus Notes</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body class="cover">
  <main class="plate">
    <p class="plate-kicker">Campus Notes</p>
    <h1 class="plate-title">Page unavailable</h1>
    <p class="stamp stamp-error"><?= e($message) ?></p>
    <a class="pencil" href="/">Back to my notes</a>
  </main>
</body>
</html>
