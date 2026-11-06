<?php
declare(strict_types=1);

// Shared request setup: error handling, security headers, sessions, database, CSRF.

const SESSION_IDLE_SECONDS = 1800;

function is_https(): bool
{
    return ($_SERVER['HTTPS'] ?? 'off') !== 'off';
}

function boot(): void
{
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    error_reporting(E_ALL);

    set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    set_exception_handler(static function (Throwable $e): void {
        // Log the type and location only: driver messages can contain SQL or credentials.
        error_log(sprintf('[campus-notes] %s at %s:%d', $e::class, basename($e->getFile()), $e->getLine()));
        abort(500, 'Something went wrong. Please try again.');
    });

    send_security_headers();
    start_secure_session();
}

function send_security_headers(): void
{
    header("Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000');
    }
}

function start_secure_session(): void
{
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    session_name('campus_notes');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();

    if (isset($_SESSION['user_id'])) {
        if (time() - ($_SESSION['last_activity'] ?? 0) > SESSION_IDLE_SECONDS) {
            $_SESSION = [];
            session_regenerate_id(true);
        } else {
            $_SESSION['last_activity'] = time();
        }
    }
}

function db(): PDO
{
    static $db = null;
    if ($db instanceof PDO) {
        return $db;
    }
    $user = getenv('LAB_DB_USER');
    $password = getenv('LAB_DB_PASSWORD');
    if ($user === false || $user === '' || $password === false) {
        // Fail closed: there is deliberately no fallback to root.
        throw new RuntimeException('Database credentials are not configured.');
    }
    $db = new PDO('mysql:host=localhost;dbname=notes_lab;charset=utf8mb4', $user, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $db;
}

function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string
{
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

function csrf_valid(mixed $token): bool
{
    return is_string($token) && hash_equals(csrf_token(), $token);
}

/** Rejects requests a browser marks as coming from another site. Our own origin is the only one allowed. */
function same_origin_request(): bool
{
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
    if ($site !== '' && !in_array($site, ['same-origin', 'none'], true)) {
        return false;
    }
    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    $self = (is_https() ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? '');
    return $origin === null || $origin === $self;
}

function flash(string $message, bool $isError = false): void
{
    $_SESSION['flash'] = ['text' => $message, 'error' => $isError];
}

function take_flash(): ?array
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $flash;
}

/** Stops the request with a fixed public message. Never pass exception text here. */
function abort(int $status, string $message): never
{
    http_response_code($status);
    if (defined('IS_API')) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => $message]);
    } else {
        header('Content-Type: text/html; charset=utf-8');
        require __DIR__ . '/../templates/error.php';
    }
    exit;
}

function redirect_home(): never
{
    header('Location: /');
    exit;
}
