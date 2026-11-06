<?php
declare(strict_types=1);

// Every note query is scoped to its owner, so callers cannot forget the check.

const NOTE_TITLE_MAX = 120;
const NOTE_BODY_MAX = 10000;

function parse_id(mixed $value): ?int
{
    if (!is_int($value) && !is_string($value)) {
        return null;
    }
    $id = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    return $id === false ? null : $id;
}

/** Returns [title, body], or null if either value is not acceptable. */
function validate_note(mixed $title, mixed $body): ?array
{
    if (!is_string($title) || !is_string($body)) {
        return null;
    }
    if (!mb_check_encoding($title, 'UTF-8') || !mb_check_encoding($body, 'UTF-8')) {
        return null;
    }
    $title = trim($title);
    $body = trim($body);
    if ($title === '' || $body === '') {
        return null;
    }
    if (mb_strlen($title, 'UTF-8') > NOTE_TITLE_MAX || mb_strlen($body, 'UTF-8') > NOTE_BODY_MAX) {
        return null;
    }
    return [$title, $body];
}

function list_notes(int $userId): array
{
    $stmt = db()->prepare('SELECT id, user_id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC');
    $stmt->execute([$userId]);
    return $stmt->fetchAll();
}

function find_note(int $id, int $userId): ?array
{
    $stmt = db()->prepare('SELECT id, user_id, title, body FROM notes WHERE id = ? AND user_id = ?');
    $stmt->execute([$id, $userId]);
    return $stmt->fetch() ?: null;
}

function create_note(int $userId, string $title, string $body): void
{
    $stmt = db()->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
    $stmt->execute([$userId, $title, $body]);
}

/** Returns false if the note does not exist or belongs to someone else. */
function update_note(int $id, int $userId, string $title, string $body): bool
{
    if (find_note($id, $userId) === null) {
        return false; // rowCount() cannot tell "not yours" from "nothing changed".
    }
    $stmt = db()->prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?');
    $stmt->execute([$title, $body, $id, $userId]);
    return true;
}

function delete_note(int $id, int $userId): bool
{
    $stmt = db()->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
    $stmt->execute([$id, $userId]);
    return $stmt->rowCount() > 0;
}
