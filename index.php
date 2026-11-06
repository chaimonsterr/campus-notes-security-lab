<?php
declare(strict_types=1);

require __DIR__ . '/src/bootstrap.php';
require __DIR__ . '/src/auth.php';
require __DIR__ . '/src/notes.php';

boot();

const NOTE_RULES = 'A note needs a title (up to 120 characters) and a body (up to 10,000).';

function post_string(string $key): string
{
    $value = $_POST[$key] ?? '';
    return is_string($value) ? $value : '';
}

function require_user(): int
{
    return current_user_id() ?? abort(401, 'Please sign in to continue.');
}

function handle_post(string $action): never
{
    switch ($action) {
        case 'register':
            $email = trim(post_string('email'));
            $password = post_string('password');
            if (!valid_credentials_format($email, $password)) {
                flash('Enter a valid email and a password of 12 to 72 characters.', true);
            } elseif (register_user($email, $password)) {
                flash('Account created. You can sign in now.');
            } else {
                flash('That account could not be created.', true);
            }
            redirect_home();

        case 'login':
            if (!attempt_login(trim(post_string('email')), post_string('password'))) {
                flash('Email or password is incorrect.', true);
            }
            redirect_home();

        case 'logout':
            logout();
            redirect_home();

        case 'save':
            $userId = require_user();
            $note = validate_note($_POST['title'] ?? null, $_POST['body'] ?? null);
            if ($note === null) {
                flash(NOTE_RULES, true);
            } else {
                create_note($userId, ...$note);
                flash('Note saved.');
            }
            redirect_home();

        case 'update':
            $userId = require_user();
            $id = parse_id($_POST['id'] ?? null) ?? abort(400, 'That request was not valid.');
            $note = validate_note($_POST['title'] ?? null, $_POST['body'] ?? null);
            if ($note === null) {
                flash(NOTE_RULES, true);
            } elseif (update_note($id, $userId, ...$note)) {
                flash('Note updated.');
            } else {
                abort(404, 'That note could not be found.');
            }
            redirect_home();

        case 'delete':
            $userId = require_user();
            $id = parse_id($_POST['id'] ?? null) ?? abort(400, 'That request was not valid.');
            if (!delete_note($id, $userId)) {
                abort(404, 'That note could not be found.');
            }
            flash('Note deleted.');
            redirect_home();
    }
    abort(400, 'That request was not valid.');
}

$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'POST') {
    if (!same_origin_request() || !csrf_valid($_POST['csrf'] ?? null)) {
        abort(403, 'This form has expired. Go back, reload the page and try again.');
    }
    handle_post(post_string('action'));
}
if ($method !== 'GET' && $method !== 'HEAD') {
    header('Allow: GET, HEAD, POST');
    abort(405, 'That request method is not supported.');
}

$userId = current_user_id();
$notes = [];
$editing = null;
if ($userId !== null) {
    $notes = list_notes($userId);
    if (isset($_GET['edit'])) {
        $id = parse_id($_GET['edit']) ?? abort(400, 'That request was not valid.');
        $editing = find_note($id, $userId) ?? abort(404, 'That note could not be found.');
    }
}

header('Content-Type: text/html; charset=utf-8');
$flash = take_flash();
require __DIR__ . '/templates/app.php';
