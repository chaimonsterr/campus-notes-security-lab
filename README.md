# Campus Notes: repaired security lab

This is the repaired version of the Campus Notes security review project. Run this project only on an isolated machine you control, with synthetic data and a disposable local database. Do not deploy it or use real accounts. The laboratory handout defines the assignment, and the findings are in the submitted Google Document.

No Composer packages are used. PHP's standard library covers hashing, sessions, PDO and JSON.

## Project layout

```text
index.php               Web pages and form actions
api.php                 JSON API
app.css                 Styles
src/
  bootstrap.php         Errors, security headers, session, database, CSRF, origin check
  auth.php              Registration, login, logout
  notes.php             Note validation and owner-scoped queries
templates/
  app.php               Sign-in page and notes page
  error.php             Generic error page
tests/
  security_check.php    Black-box security checks
schema.sql              Database, tables and synthetic seed data
```

## Local setup

1. Install a supported PHP 8 release with `pdo_mysql` and `mbstring`, plus a local MySQL or MariaDB server. Confirm the extensions appear in `php -m`.
2. As a local database administrator, import `schema.sql` into a fresh disposable server. It creates `notes_lab` and its tables.
3. Create a dedicated local account with SELECT, INSERT, UPDATE and DELETE only on `notes_lab`. Do not use root: the app has no fallback account and returns a generic error if credentials are missing.

   ```sql
   CREATE USER 'notes_app'@'localhost' IDENTIFIED BY 'choose-a-local-password';
   GRANT SELECT, INSERT, UPDATE, DELETE ON notes_lab.* TO 'notes_app'@'localhost';
   ```

4. Set the credentials for your shell. Do not commit them.

   ```powershell
   $env:LAB_DB_USER = 'notes_app'
   $env:LAB_DB_PASSWORD = 'your_local_password'
   ```

5. From this folder, start the server. Use another port if 8000 is taken. The PHP built-in server is for local development only.

   ```powershell
   php -S 127.0.0.1:8000
   ```

6. The schema includes two synthetic accounts, now stored with `password_hash()`:
   - `alex@example.test` / `LabOnly-Alex-123`
   - `sam@example.test` / `LabOnly-Sam-456`

   These are the public, throwaway credentials from the starter project. Never reuse them elsewhere.

## API

The API is same-origin and uses the session cookie.

- `GET /api.php` lists your own notes and returns a CSRF token in the `X-CSRF-Token` response header. `?user_id=` is optional and must be your own ID.
- `POST /api.php` updates one of your notes. It needs `Content-Type: application/json`, an `X-CSRF-Token` request header, and a JSON object with `id`, `title` and `body`.

## Running the security checks

With the app running and the same `LAB_DB_*` variables set:

```powershell
php tests/security_check.php http://127.0.0.1:8000
```

Each run registers two random throwaway users. To include the database-failure checks, also start a second server with a wrong `LAB_DB_PASSWORD` and pass its URL as a second argument.

## Production limits

Local HTTP is for this exercise only. A real deployment needs HTTPS, which turns on the `Secure` cookie flag and HSTS in this code, plus login rate limiting, a managed secret store, log monitoring, and email verification.
