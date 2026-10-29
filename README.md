# Task Manager API authentication

## Email signup verification

New accounts are created only after the user verifies a six-digit OTP sent to their email. Configure these environment variables for the API process; do not commit their values:

- `SECRET_KEY`: secret used to sign access tokens.
- `OTP_SECRET_KEY`: optional separate secret used to hash signup OTPs. If omitted, `SECRET_KEY` is used.
- `SMTP_HOST`, `SMTP_PORT`: outgoing mail server and port.
- `SMTP_USERNAME`, `SMTP_PASSWORD`: SMTP login credentials (for Gmail, use an App Password, not your normal account password).
- `SMTP_FROM_EMAIL`: sender address accepted by your mail provider.
- `SMTP_USE_TLS`, `SMTP_USE_SSL`: select STARTTLS (587) or implicit SSL (465); do not enable both.
- `FRONTEND_BASE_URL`: frontend origin used in admin invitation links (defaults to `http://localhost:5173`).

For Gmail, use `smtp.gmail.com`, port `587`, and STARTTLS (`SMTP_USE_TLS=true`, `SMTP_USE_SSL=false`). Enable 2-Step Verification on the Google account and create an App Password for SMTP. Store it in `SMTP_PASSWORD`; do not use or share your normal Gmail password. For another email provider, use its SMTP host, port, and required security mode. Copy `.env.example` to `.env` as a reference and keep `.env` private.

For local frontend development, set `VITE_API_BASE_URL=http://127.0.0.1:8000` in the frontend environment. The frontend defaults to the existing hosted API URL, which must be redeployed with these backend changes for the new features to work there.

The signup flow is `POST /signup` with `email` and `password` (at least 8 characters), followed by `POST /signup/verify` with the email and six-digit `code`. Codes expire after 10 minutes; resends are limited to one per minute and verification allows at most five incorrect attempts.

## Roles and admin access

Public signup always creates a regular `user`; clients cannot choose their own role. Admins can view accounts at `GET /admin/users` and change roles at `PATCH /admin/users/{user_id}/role` using `{"role":"admin"}` or `{"role":"user"}`. These endpoints are enforced by the API, not just hidden in the frontend.

Admins can invite an admin using `POST /admin/signup` with an admin bearer token and `{"email":"new-admin@example.com"}`. The invitee receives an email OTP and completes setup at `/admin/complete-signup`, choosing their own password. `POST /admin/signup/verify` verifies the invitation code and creates the admin account. The invitation request is admin-protected; completion requires the emailed OTP. For a deployed frontend, set `FRONTEND_BASE_URL` to its public origin so invitation links point to the deployed app.

On startup, the API creates the OTP table and adds the `phone` and `role` columns to an existing `users` table, and adds the `role` column to an existing `pending_signups` table. To grant the first administrator, update a trusted account directly in the database, for example:

```sql
UPDATE users SET role = 'admin' WHERE email = 'trusted-admin@example.com';
```

The database user used for this one-time change should be restricted to trusted operators. At least one admin must remain assigned.