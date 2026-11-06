<?php
declare(strict_types=1);

// Black-box security checks. Registers two random throwaway users on every run.
// Usage: php tests/security_check.php http://127.0.0.1:8123 [url-of-server-with-bad-db-password]
// Needs LAB_DB_USER and LAB_DB_PASSWORD so results can be confirmed in the database.

$base = rtrim($argv[1] ?? 'http://127.0.0.1:8000', '/');
$brokenBase = isset($argv[2]) ? rtrim($argv[2], '/') : null;
$results = [];

function check(string $id, string $name, bool $passed): void
{
    global $results;
    $results[] = $passed;
    printf("%-4s %-4s %s\n", $id, $passed ? 'PASS' : 'FAIL', $name);
}

final class Client
{
    public array $cookies = [];
    public int $status = 0;
    public string $body = '';
    public array $headers = [];

    public function __construct(private string $base) {}

    public function send(string $method, string $path, string|array|null $data = null, array $headers = []): static
    {
        $curl = curl_init($this->base . $path);
        $cookie = implode('; ', array_map(fn ($k, $v) => "$k=$v", array_keys($this->cookies), $this->cookies));
        if ($cookie !== '') {
            $headers[] = "Cookie: $cookie";
        }
        $this->headers = [];
        curl_setopt_array($curl, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADERFUNCTION => function ($c, string $line): int {
                $this->headers[] = trim($line);
                if (preg_match('/^set-cookie:\s*([^=]+)=([^;]*)/i', $line, $m)) {
                    if ($m[2] === '' || $m[2] === 'deleted') {
                        unset($this->cookies[$m[1]]);
                    } else {
                        $this->cookies[$m[1]] = $m[2];
                    }
                }
                return strlen($line);
            },
        ]);
        if ($data !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, is_array($data) ? http_build_query($data) : $data);
        }
        $this->body = (string) curl_exec($curl);
        $this->status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);
        return $this;
    }

    public function get(string $path, array $headers = []): static
    {
        return $this->send('GET', $path, null, $headers);
    }

    public function csrf(): string
    {
        $this->get('/');
        preg_match('/name="csrf" value="([a-f0-9]+)"/', $this->body, $m);
        return $m[1] ?? '';
    }

    public function form(array $fields): static
    {
        return $this->send('POST', '/', $fields + ['csrf' => $this->csrf()]);
    }

    public function apiToken(): string
    {
        $this->get('/api.php');
        foreach ($this->headers as $line) {
            if (stripos($line, 'x-csrf-token:') === 0) {
                return trim(substr($line, 13));
            }
        }
        return '';
    }

    public function headerLine(string $prefix): string
    {
        foreach ($this->headers as $line) {
            if (stripos($line, $prefix) === 0) {
                return $line;
            }
        }
        return '';
    }
}

$pdo = new PDO('mysql:host=localhost;dbname=notes_lab;charset=utf8mb4', getenv('LAB_DB_USER'), getenv('LAB_DB_PASSWORD'), [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$value = function (string $sql, array $args = []) use ($pdo): mixed {
    $stmt = $pdo->prepare($sql);
    $stmt->execute($args);
    return $stmt->fetchColumn();
};

$run = bin2hex(random_bytes(4));
$aEmail = "a-$run@example.test";
$bEmail = "b-$run@example.test";
$aPass = bin2hex(random_bytes(12));
$bPass = bin2hex(random_bytes(12));
$a = new Client($base);
$b = new Client($base);
$anon = new Client($base);
$json = ['Content-Type: application/json'];

// Accounts and login
$a->form(['action' => 'register', 'email' => $aEmail, 'password' => $aPass, 'role' => 'admin']);
$b->form(['action' => 'register', 'email' => $bEmail, 'password' => $bPass]);
$aId = (int) $value('SELECT id FROM users WHERE email = ?', [$aEmail]);
$bId = (int) $value('SELECT id FROM users WHERE email = ?', [$bEmail]);
check('A1', 'Registration creates both users', $aId > 0 && $bId > 0);
check('A2', 'Client-sent role=admin is ignored (stored as student)', $value('SELECT role FROM users WHERE id = ?', [$aId]) === 'student');
check('A3', 'Password stored with password_hash, not MD5', password_get_info((string) $value('SELECT password_hash FROM users WHERE id = ?', [$aId]))['algo'] !== null);

$badLogin = new Client($base);
$badLogin->form(['action' => 'login', 'email' => $aEmail, 'password' => 'wrong-password-here']);
$badLogin->get('/');
check('A4', 'Wrong password is refused with a generic message', str_contains($badLogin->body, 'Email or password is incorrect') && !str_contains($badLogin->body, $aEmail));

$sqli = new Client($base);
$sqli->form(['action' => 'login', 'email' => "' OR 1=1 -- ", 'password' => 'x']);
$sqli->get('/');
check('A5', 'SQL injection in login does not sign in', !str_contains($sqli->body, 'Log out') && $sqli->get('/api.php')->status === 401);

$before = $a->csrf();
$sessionBefore = $a->cookies['campus_notes'] ?? '';
$a->form(['action' => 'login', 'email' => $aEmail, 'password' => $aPass]);
$b->form(['action' => 'login', 'email' => $bEmail, 'password' => $bPass]);
$a->get('/');
check('A6', 'Valid login reaches the notes page', str_contains($a->body, 'Log out') && str_contains($a->body, 'My notes'));
check('S1', 'Session ID changes at login', $sessionBefore !== '' && ($a->cookies['campus_notes'] ?? '') !== $sessionBefore);

$fixed = new Client($base);
$fixed->cookies['campus_notes'] = 'attackerchosenid123';
$fixed->form(['action' => 'login', 'email' => $aEmail, 'password' => $aPass]);
check('S2', 'A session ID chosen by the client is replaced', ($fixed->cookies['campus_notes'] ?? '') !== 'attackerchosenid123');

$probe = (new Client($base))->get('/');
$cookie = strtolower($probe->headerLine('set-cookie:'));
check('S3', 'Session cookie has HttpOnly and SameSite=Lax', str_contains($cookie, 'httponly') && str_contains($cookie, 'samesite=lax'));

// Note ownership
$a->form(['action' => 'save', 'title' => "private-$run", 'body' => 'alpha', 'user_id' => $bId]);
$noteId = (int) $value('SELECT id FROM notes WHERE title = ?', ["private-$run"]);
check('O1', 'Client-sent owner is ignored (note belongs to the signed-in user)', (int) $value('SELECT user_id FROM notes WHERE id = ?', [$noteId]) === $aId);

$b->get('/');
check('O2', "Other user's notes are not listed", !str_contains($b->body, "private-$run"));
check('O3', "Other user's note cannot be opened for edit (404)", $b->get("/?edit=$noteId")->status === 404 && !str_contains($b->body, "private-$run"));
$b->form(['action' => 'update', 'id' => $noteId, 'title' => 'stolen', 'body' => 'stolen']);
check('O4', "Other user's note cannot be updated (404, unchanged)", $b->status === 404 && $value('SELECT title FROM notes WHERE id = ?', [$noteId]) === "private-$run");
$b->form(['action' => 'delete', 'id' => $noteId]);
check('O5', "Other user's note cannot be deleted (404, still there)", $b->status === 404 && (int) $value('SELECT COUNT(*) FROM notes WHERE id = ?', [$noteId]) === 1);

$a->form(['action' => 'update', 'id' => $noteId, 'title' => "private-$run", 'body' => 'alpha edited']);
check('O6', 'Owner can update own note', $value('SELECT body FROM notes WHERE id = ?', [$noteId]) === 'alpha edited');

// Output handling
$payload = '<script>alert(1)</script><img src=x onerror=alert(2)>';
$a->form(['action' => 'save', 'title' => $payload, 'body' => $payload]);
$a->get('/');
check('X1', 'HTML in notes renders as text', !str_contains($a->body, '<script>alert') && !str_contains($a->body, '<img src=x') && str_contains($a->body, '&lt;script&gt;'));
$xssId = (int) $value('SELECT id FROM notes WHERE title = ? AND user_id = ?', [$payload, $aId]);
$a->get("/?edit=$xssId");
check('X2', 'HTML is escaped inside the edit form', !str_contains($a->body, '<script>alert') && !str_contains($a->body, 'value="<'));
check('X3', 'message= URL parameter is not reflected', !str_contains((new Client($base))->get('/?message=%3Cimg%20src=x%3E')->body, '<img src=x'));
check('X4', 'Content-Security-Policy blocks inline script', str_contains($a->headerLine('content-security-policy:'), "default-src 'none'"));

// CSRF and unsafe methods
$counts = fn (): int => (int) $value('SELECT COUNT(*) FROM notes WHERE id = ?', [$noteId]);
$a->send('POST', '/', ['action' => 'delete', 'id' => $noteId]);
check('C1', 'POST without a CSRF token is rejected (403)', $a->status === 403 && $counts() === 1);
$a->send('POST', '/', ['action' => 'delete', 'id' => $noteId, 'csrf' => str_repeat('0', 64)]);
check('C2', 'POST with a wrong CSRF token is rejected (403)', $a->status === 403 && $counts() === 1);
$a->send('POST', '/', ['action' => 'delete', 'id' => $noteId, 'csrf' => $a->csrf()], ['Origin: http://evil.test']);
check('C3', 'Valid token from an untrusted Origin is rejected (403)', $a->status === 403 && $counts() === 1);
$a->get("/?delete=$noteId");
check('C4', 'GET ?delete= no longer deletes', $counts() === 1);
$a->get('/?logout=1');
$a->get('/');
check('C5', 'GET ?logout=1 no longer logs out', str_contains($a->body, 'Log out'));

// API: authentication and per-record authorization
check('P1', 'API GET with no session returns 401', $anon->get("/api.php?user_id=$aId")->status === 401 && !str_contains($anon->body, 'private-'));
check('P2', 'API POST with no session returns 401', $anon->send('POST', '/api.php', json_encode(['id' => $noteId, 'title' => 'x', 'body' => 'x']), $json)->status === 401);
check('P3', "API GET for another user's ID returns 403", $b->get("/api.php?user_id=$aId")->status === 403 && !str_contains($b->body, 'private-'));
$a->get('/api.php');
$list = json_decode($a->body, true);
check('P4', 'API GET returns only own notes', is_array($list) && $list !== [] && array_unique(array_column($list, 'user_id')) === [$aId]);
$bToken = $b->apiToken();
$b->send('POST', '/api.php', json_encode(['id' => $noteId, 'title' => 'stolen', 'body' => 'stolen']), [...$json, "X-CSRF-Token: $bToken"]);
check('P5', "API update of another user's note returns 404, unchanged", $b->status === 404 && $value('SELECT title FROM notes WHERE id = ?', [$noteId]) === "private-$run");
$aToken = $a->apiToken();
$apiHeaders = [...$json, "X-CSRF-Token: $aToken"];
$a->send('POST', '/api.php', json_encode(['id' => $noteId, 'title' => "api-$run", 'body' => 'via api']), $apiHeaders);
check('P6', 'API update of own note succeeds', $a->status === 200 && $value('SELECT title FROM notes WHERE id = ?', [$noteId]) === "api-$run");

// API: validation
$cleanError = fn (Client $c): bool => is_array(json_decode($c->body, true)) && !preg_match('/Warning|Fatal|Stack trace|\.php/', $c->body);
$a->send('POST', '/api.php', '{bad', $apiHeaders);
check('V1', 'Malformed JSON returns 400 with a clean JSON error', $a->status === 400 && $cleanError($a));
foreach ([
    'V2' => ['JSON scalar body', '42'],
    'V3' => ['JSON list body', '[1,2]'],
    'V4' => ['Missing fields', '{"id":1}'],
    'V5' => ['Array as title', json_encode(['id' => $noteId, 'title' => ['x'], 'body' => 'x'])],
    'V6' => ['Boolean as id', json_encode(['id' => true, 'title' => 'x', 'body' => 'x'])],
    'V7' => ['Negative id', json_encode(['id' => -1, 'title' => 'x', 'body' => 'x'])],
    'V8' => ['Title over 120 characters', json_encode(['id' => $noteId, 'title' => str_repeat('x', 121), 'body' => 'x'])],
] as $id => [$name, $body]) {
    $a->send('POST', '/api.php', $body, $apiHeaders);
    check($id, "$name returns 400", $a->status === 400 && $cleanError($a));
}
check('V9', 'Oversized body returns 413', $a->send('POST', '/api.php', str_repeat(' ', 70000), $apiHeaders)->status === 413);
check('V10', 'Unsupported method returns 405', $a->send('PUT', '/api.php', '{}', $apiHeaders)->status === 405);

// API: cross-origin and CSRF
$noCors = fn (Client $c): bool => $c->headerLine('access-control-') === '';
$a->get('/api.php', ['Origin: http://evil.test']);
check('R1', 'API GET from an untrusted Origin returns 403 with no CORS headers', $a->status === 403 && $noCors($a) && !str_contains($a->body, 'private-'));
$a->send('OPTIONS', '/api.php', null, ['Origin: http://evil.test', 'Access-Control-Request-Method: POST']);
check('R2', 'Preflight from an untrusted Origin gets no CORS headers', $noCors($a));
$a->send('POST', '/api.php', json_encode(['id' => $noteId, 'title' => 'x', 'body' => 'x']), [...$apiHeaders, 'Origin: http://evil.test']);
check('R3', 'API POST from an untrusted Origin returns 403', $a->status === 403);
$a->send('POST', '/api.php', json_encode(['id' => $noteId, 'title' => 'x', 'body' => 'x']), $json);
check('R4', 'API POST without a CSRF token returns 403', $a->status === 403);
$a->send('POST', '/api.php', json_encode(['id' => $noteId, 'title' => 'x', 'body' => 'x']), ['Content-Type: text/plain', "X-CSRF-Token: $aToken"]);
check('R5', 'API POST with a form-style content type returns 415', $a->status === 415);
$a->get('/api.php', ['Sec-Fetch-Site: cross-site']);
check('R6', 'API GET marked cross-site by the browser returns 403', $a->status === 403);

// Configuration exposure
check('F1', 'Template files cannot be opened directly (404)', (new Client($base))->get('/templates/app.php')->status === 404);
check('F2', 'Opening src/bootstrap.php directly shows nothing', (new Client($base))->get('/src/bootstrap.php')->body === '');
check('E1', 'Unknown action is a plain 400 with no internals', (function () use ($a): bool {
    $a->form(['action' => 'nope']);
    return $a->status === 400 && !preg_match('/SQLSTATE|Stack trace|\.php/', $a->body);
})());
if ($brokenBase !== null) {
    $broken = (new Client($brokenBase))->form(['action' => 'login', 'email' => $aEmail, 'password' => $aPass]);
    check('E2', 'Database failure shows a generic 500 page', $broken->status === 500 && !preg_match('/SQLSTATE|PDO|Stack trace|notes_app|\.php/', $broken->body));
    check('E3', 'Failure page keeps the security headers', $broken->headerLine('content-security-policy:') !== '');
}

// Logout, checked last because it ends the session
$oldCookie = $a->cookies;
$a->form(['action' => 'logout']);
$a->get('/');
check('L1', 'Logout returns to the sign-in page', str_contains($a->body, 'Sign in') && !str_contains($a->body, 'Log out'));
$replay = new Client($base);
$replay->cookies = $oldCookie;
check('L2', 'The old session cookie no longer works', $replay->get('/api.php')->status === 401);

$failed = count(array_filter($results, fn (bool $r): bool => !$r));
printf("\n%d checks, %d passed, %d failed\n", count($results), count($results) - $failed, $failed);
exit($failed === 0 ? 0 : 1);
