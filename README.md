# Hostel Management Pro

A standalone Flask + SQLite hostel operations app. It contains student directory and room history, room occupancy, leave requests and approvals, complaints/maintenance, notices, mess menu, fee records, visitor register, lost & found, reports, CSV student export, SQLite database backup, accounts/roles, password change and downloadable student QR links.

## Run on Windows PowerShell

Open PowerShell in the folder containing `app.py`:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000

## First login

- Username: `admin`
- Password: `admin123`

Change the default password at **Password** after signing in. Set `HOSTEL_ADMIN_PASSWORD` before first launch if you want to define the initial admin password, and set a strong `HOSTEL_SECRET_KEY` in your environment before any shared/network deployment. The demo admin is created only when the database has no admin account; changing the environment variable later will not reset an existing password.

## Features

- Public student directory and profile pages (avoid storing sensitive data in public profiles)
- Admin/warden student management and student-photo upload (PNG/JPG/WEBP, max 5 MB)
- Room capacity/occupancy and room-allocation history
- Student-linked account portal; leave request submission/approval
- Complaint submission, assignment and status tracking
- Notice board and mess menu
- Fee record tracking (not an online payment gateway)
- Visitor entry/check-out
- Lost & found board
- Account/role management, password change, reports, CSV export, database backup, QR codes
- Animated responsive blue/white interface

## Roles

`admin` can manage all features/accounts. `warden` can manage residents and operational records. `maintenance` can update complaints. `student` can access their linked portal, submit their own leave request, lodge complaints and see their own fee/leave records.

Create accounts from **Accounts** after logging in as admin. For student accounts, link the account to an existing student record.

## Important limitations / deployment

- This is a starter project intended for local development; before real student data or internet exposure, review and test security, add CSRF protection, HTTPS, strict secret-key management, database backup scheduling and an appropriate privacy policy.
- Profile and directory fields such as student names, course, room and phone should be reviewed before public use. This starter keeps phone fields in the profile data; don't publish it with real personal data until access rules are adjusted to your institution's policy.
- Fee records are manual records only; no money is collected. No SMS, WhatsApp or email delivery is configured.
- SQLite is suitable for a small prototype. Plan a managed database and backup/restore process before multi-user production use.
