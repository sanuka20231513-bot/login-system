# Simple Login System (with Admin Approval) — SQLite version

A beginner-friendly login system built with **Flask (Python)** for the
server logic, **SQLite** for storage, and plain **HTML/CSS/JavaScript**
for the pages.

## Folder structure

```
login-system/
├── app.py                 <- all server-side logic (routes, database access)
├── schema.sql              <- the users table structure (for reference)
├── users.db                 <- auto-created SQLite database (not in git)
├── users.txt                 <- legacy seed data, imported into users.db once
├── requirements.txt           <- just Flask
├── templates/                  <- HTML pages (rendered by Flask)
│   ├── login.html
│   ├── register.html
│   ├── forgot_password.html
│   ├── reset_password.html
│   ├── dashboard.html
│   ├── admin_login.html
│   ├── admin_panel.html
│   └── edit_user.html
└── static/
    ├── style.css
    └── script.js
```

## How to run it

```bash
pip install -r requirements.txt
python app.py
```

Then open:
- **User login:** http://127.0.0.1:5000/
- **Register:** http://127.0.0.1:5000/register
- **Admin login:** http://127.0.0.1:5000/admin (`admin` / `admin123`)

## The database (users.db)

Storage moved from a plain text file to a small **SQLite** database.
SQLite needs no separate server — it's just a single `.db` file that
Python's built-in `sqlite3` module reads and writes directly.

Table structure (see `schema.sql`):

```sql
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email    TEXT,
    password TEXT NOT NULL,
    status   TEXT NOT NULL DEFAULT 'Pending'
);
```

`app.py` creates this table automatically on first run (`init_db()`).
If `users.db` doesn't exist yet and an old `users.txt` file is found next
to it, the accounts in `users.txt` are imported once so no demo data is
lost — after that, `users.txt` is no longer read or written.

> **Security note:** passwords are still stored as plain text to keep the
> project simple, as originally intended. Fine for a demo/viva; a real
> app should hash passwords with `werkzeug.security`.

## What's new: Email field + Admin Edit

- **Register** now also asks for an **email address**, stored alongside
  name/username/password/status.
- **Admin Panel** now has an **Edit** button on every user row (Pending,
  Approved, Rejected/Disabled). Clicking it opens `edit_user.html`, where
  the admin can change that user's **name, username, and email** directly
  — a small user-management "profile editor" on top of the existing
  Approve/Reject/Disable/Remove actions.
- Editing checks that a new username isn't already taken by someone else
  before saving (`update_user_details()` in `app.py`).

## How the flow works

1. **Register**: `/register` collects name, username, email, password →
   inserted into `users.db` with status `Pending`.
2. **Login**: `/` checks credentials and `status` — only `Approved`
   accounts can log in; `Pending`/`Rejected`/`Disabled` show a specific
   message.
3. **Admin approval**: `/admin/panel` lists users grouped by status;
   Approve/Reject/Disable/Remove buttons POST to routes that update the
   database.
4. **Admin edit**: `/admin/edit/<username>` (GET shows the form, POST
   saves changes) lets the admin correct a user's name/username/email.
5. **Forgot password**: `/forgot-password` verifies the username exists,
   then `/reset-password` lets the user set a new password — both now
   read/write through the database instead of the text file.

## Extending it further

- Add more fields (phone, address, etc.) — add a column via
  `ALTER TABLE users ADD COLUMN ...` (or just edit `schema.sql` and
  delete `users.db` to start fresh), then update the forms/templates.
- Swap plain-text passwords for hashed ones with
  `werkzeug.security.generate_password_hash` / `check_password_hash`.
