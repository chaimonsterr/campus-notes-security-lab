<?php
declare(strict_types=1);

// Accounts and login. Roles are decided here, never by the client.

const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_MAX_BYTES = 72; // bcrypt ignores anything longer.
// Checked when an email is unknown, so both login failures take about the same time.
const DUMMY_HASH = '$2y$10$g7vAhzrrkzhDaFfZ6cOtMuBg8Zl59.F1q6qFIA0W535cHFwvpQUCG';

function current_user_id(): ?int
{
    return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
}

function valid_credentials_format(string $email, string $password): bool
{
    return strlen($email) <= 254
        && filter_var($email, FILTER_VALIDATE_EMAIL) !== false
        && mb_check_encoding($password, 'UTF-8')
        && mb_strlen($password, 'UTF-8') >= PASSWORD_MIN_LENGTH
        && strlen($password) <= PASSWORD_MAX_BYTES;
}

/** Returns false when the email is already taken. */
function register_user(string $email, string $password): bool
{
    $stmt = db()->prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)');
    try {
        $stmt->execute([$email, password_hash($password, PASSWORD_DEFAULT), 'student']);
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') {
            return false;
        }
        throw $e;
    }
    return true;
}

function attempt_login(string $email, string $password): bool
{
    $stmt = db()->prepare('SELECT id, email, password_hash, role FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    $matches = password_verify($password, $user['password_hash'] ?? DUMMY_HASH);
    if (!$user || !$matches) {
        // No email in the log: it is attacker-controlled text.
        error_log('[campus-notes] failed login from ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        return false;
    }

    if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
        $update = db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $update->execute([password_hash($password, PASSWORD_DEFAULT), $user['id']]);
    }

    session_regenerate_id(true);
    $_SESSION = [
        'user_id' => (int) $user['id'],
        'email' => $user['email'],
        'role' => $user['role'],
        'last_activity' => time(),
    ];
    return true;
}

function logout(): void
{
    $_SESSION = [];
    $cookie = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 3600,
        'path' => $cookie['path'],
        'secure' => $cookie['secure'],
        'httponly' => $cookie['httponly'],
        'samesite' => $cookie['samesite'],
    ]);
    session_destroy();
}
