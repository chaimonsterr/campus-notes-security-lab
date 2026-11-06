<?php
declare(strict_types=1);

define('IS_API', true);

require __DIR__ . '/src/bootstrap.php';
require __DIR__ . '/src/auth.php';
require __DIR__ . '/src/notes.php';

const API_MAX_BYTES = 65536;

boot();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

// Same-origin only: no Access-Control-* headers are ever sent.
if (!same_origin_request()) {
    abort(403, 'Origin not allowed.');
}

$userId = current_user_id() ?? abort(401, 'Authentication required.');
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    if (isset($_GET['user_id'])) {
        $requested = parse_id($_GET['user_id']) ?? abort(400, 'Invalid user_id.');
        if ($requested !== $userId) {
            abort(403, 'Forbidden.');
        }
    }
    header('X-CSRF-Token: ' . csrf_token());
    echo json_encode(list_notes($userId), JSON_THROW_ON_ERROR);
    exit;
}

if ($method === 'POST') {
    // A cross-site HTML form cannot send this content type or header.
    $contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
    if ($contentType !== 'application/json') {
        abort(415, 'Content-Type must be application/json.');
    }
    if (!csrf_valid($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) {
        abort(403, 'Invalid CSRF token.');
    }
    $raw = file_get_contents('php://input', false, null, 0, API_MAX_BYTES + 1);
    if (strlen($raw) > API_MAX_BYTES) {
        abort(413, 'Request body is too large.');
    }
    try {
        $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        abort(400, 'Malformed JSON.');
    }
    if (!is_array($data) || array_is_list($data)) {
        abort(400, 'Expected a JSON object with id, title and body.');
    }
    $id = parse_id($data['id'] ?? null);
    $note = validate_note($data['title'] ?? null, $data['body'] ?? null);
    if ($id === null || $note === null) {
        abort(400, 'id must be a positive integer; title and body must be non-empty text within limits.');
    }
    if (!update_note($id, $userId, ...$note)) {
        abort(404, 'Note not found.');
    }
    echo json_encode(['updated' => 1]);
    exit;
}

header('Allow: GET, POST');
abort(405, 'Method not supported.');
