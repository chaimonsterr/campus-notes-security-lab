<?php
if (!function_exists('e')) { http_response_code(404); exit; }
$noteCount = count($notes);
$stamp = static function (?array $flash): string {
    if ($flash === null) {
        return '';
    }
    $class = $flash['error'] ? 'stamp stamp-error' : 'stamp';
    return '<p class="' . $class . '" role="status">' . e($flash['text']) . '</p>';
};
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Campus Notes</title>
  <link rel="stylesheet" href="/app.css">
</head>
<?php if ($userId === null): ?>
<body class="cover">
  <main class="plate">
    <p class="plate-kicker">Examination book</p>
    <h1 class="plate-title">Campus Notes</h1>
    <?= $stamp($flash) ?>
    <form method="post" class="plate-form">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <label class="blank">
        <span>Email</span>
        <input name="email" type="email" maxlength="254" autocomplete="username" required>
      </label>
      <label class="blank">
        <span>Password</span>
        <input name="password" type="password" maxlength="72" autocomplete="current-password" required>
      </label>
      <div class="plate-actions">
        <button name="action" value="login">Sign in</button>
        <button name="action" value="register" class="button-plain">Register</button>
      </div>
      <p class="fine-print">New here? Fill in both lines and register. Passwords need at least 12 characters.</p>
    </form>
  </main>
</body>
<?php else: ?>
<body class="desk">
  <main class="book">
    <section class="page page-left" aria-labelledby="write-heading">
      <header class="page-head">
        <p class="owner"><?= e($_SESSION['email'] ?? '') ?> <span><?= e($_SESSION['role'] ?? '') ?></span></p>
        <form method="post">
          <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
          <button name="action" value="logout" class="pencil">Log out</button>
        </form>
      </header>
      <?= $stamp($flash) ?>
      <h1 id="write-heading"><?= $editing ? 'Edit note' : 'New note' ?></h1>
      <form method="post" class="note-form">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <?php if ($editing): ?>
        <input type="hidden" name="id" value="<?= e($editing['id']) ?>">
        <?php endif; ?>
        <label class="blank">
          <span>Title</span>
          <input name="title" maxlength="120" value="<?= e($editing['title'] ?? '') ?>" required>
        </label>
        <label class="ruled-field">
          <span>Body</span>
          <textarea name="body" rows="9" maxlength="10000" required><?= e($editing['body'] ?? '') ?></textarea>
        </label>
        <div class="note-actions">
          <button name="action" value="<?= $editing ? 'update' : 'save' ?>"><?= $editing ? 'Update note' : 'Save note' ?></button>
          <?php if ($editing): ?>
          <a class="pencil" href="/">Cancel</a>
          <?php endif; ?>
        </div>
      </form>
    </section>

    <section class="page page-right" aria-labelledby="notes-heading">
      <h2 id="notes-heading">My notes <small><?= $noteCount ?></small></h2>
      <?php if ($noteCount === 0): ?>
      <p class="empty">Nothing written yet. This page is all yours.</p>
      <?php endif; ?>
      <?php foreach ($notes as $index => $note): ?>
      <article class="entry">
        <p class="entry-no" aria-hidden="true"><?= $noteCount - $index ?></p>
        <h3><?= e($note['title']) ?></h3>
        <p class="ink"><?= e($note['body']) ?></p>
        <div class="entry-actions">
          <a class="pencil" href="/?edit=<?= e($note['id']) ?>">Edit<span class="visually-hidden"> <?= e($note['title']) ?></span></a>
          <details>
            <summary class="pencil">Delete<span class="visually-hidden"> <?= e($note['title']) ?></span></summary>
            <form method="post">
              <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="id" value="<?= e($note['id']) ?>">
              <button name="action" value="delete" class="button-danger">Yes, delete this note</button>
            </form>
          </details>
        </div>
      </article>
      <?php endforeach; ?>
    </section>
  </main>
</body>
<?php endif; ?>
</html>
