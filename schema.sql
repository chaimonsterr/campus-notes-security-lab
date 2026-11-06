CREATE DATABASE IF NOT EXISTS notes_lab CHARACTER SET utf8mb4;
USE notes_lab;

CREATE TABLE users (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin'))
);

CREATE TABLE notes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  title VARCHAR(120) NOT NULL,
  body TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Synthetic accounts for local use only. Passwords are stored with password_hash().
INSERT INTO users (id, email, password_hash, role) VALUES
  (1, 'alex@example.test', '$2y$10$28NXZ3Iwkb/Q/Y6NSnbVI.nVvpxjrTWOc5zJaDQ.msW4.4zhPd3iW', 'student'),
  (2, 'sam@example.test', '$2y$10$0BBTiMGIvHtaiSL.cCFcWOKROAwQa/5MabNrNwyFtwLsOEx1kZJBO', 'student');

INSERT INTO notes (user_id, title, body) VALUES
  (1, 'Alex: course reminder', 'Review the security reading before class.'),
  (1, 'Alex: project idea', 'Build a small student directory.'),
  (2, 'Sam: study plan', 'Compare authentication and authorization.'),
  (2, 'Sam: meeting', 'Prepare questions for the next group discussion.');
