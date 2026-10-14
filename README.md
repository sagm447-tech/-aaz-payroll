# AAZ Payroll — deployable starter

This is a **starter**, not a production-certified payroll system. Arabic RTL interface, admin-only worker/user/assignment changes, supervisor/courier access limited to assigned branches/workers, signature-based internal receipt, CSV report and audit trail.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export ADMIN_PASSWORD='CHOOSE-A-LONG-UNIQUE-PASSWORD'
export IMPORT_SAMPLE=1
python app.py
```

Open http://127.0.0.1:5000 and sign in with username `admin` and the password you set. `IMPORT_SAMPLE=1` loads the **sample September data only on first initialization**, deduplicating on the recorded document number. The imported data is sensitive: do not deploy a publicly accessible database until access controls and security are independently reviewed.

## Production requirements before real use

- Host behind HTTPS, set `HTTPS_ONLY=1`, use a durable protected database and secret key. Do not use SQLite on ephemeral hosting. Use PostgreSQL for multi-user production.
- Independent security review, rate limiting, MFA, password reset, encryption at rest, offsite backups, retention rules, user consent and privacy controls.
- Add SMS/WhatsApp provider integration with independently verified worker-owned phone numbers; the current build **does not send messages**.
- Video upload, secure storage, worker consent and retention are **not implemented**.
- Current signature is an internal receipt record, **not** a certified electronic signature. Recording a signature does not prove cash changed hands.
- Implement actual cash custody, reconciliation, partial payments, payslip approval, reversal and dual control before operational deployment.
- Confirm Saudi wage protection, employment and personal data requirements with qualified counsel/accounting advisors. Cash receipts do not replace WPS compliance.
- The sample import contains source-document anomalies, possible duplicate people and missing payables. Verify against authoritative HR records before using for payroll.

## Housing-rent extension (October 2026)

The added `rentals.py` module provides **إيجارات سكن عمال مؤسسة الزبيدي**: electronic (Ejar) or paper contract metadata, housing by region, installment schedules, bill/reference numbers, receipt PDF/JPEG/PNG upload (max 3 MB), payment submission by the rent agent, **admin-only approval**, other expenses, audit logs, and an **in-app** upcoming/overdue rent and contract-expiry alerts page. Installment approvals count as the rent expense; do not manually enter the same payment in other expenses.

Create Osama's account **only after confirming a username and setting a unique password**: as admin, go to `/users` and choose **مسؤول الإيجارات**. Rent agents can access only `/rentals`, `/alerts`, and receipt downloads; they cannot view payroll or change contracts. No account or real contract was pre-created. Saleh's admin account should be assigned/renamed through a controlled account-management process; no personal credentials are embedded in this package.

**Limitations:** Reminders are visible when visiting `/alerts`, not pushed automatically. Salary-due reminders, automated SMS/WhatsApp/push delivery, file malware scanning, hardened object storage, encryption, backups, production PostgreSQL, and external Ejar validation are not implemented. Contract identifiers are recorded, **not** validated against Ejar. The system is not deployed to Vercel/Supabase. Do not expose to the public internet or upload real workers' sensitive data without a security/privacy review. SQLite and local private_receipts storage require durable disk; ephemeral serverless hosting would lose data.
