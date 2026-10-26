# Secure Online Banking Login and Transfer System

## Abstract

This course project demonstrates a Flask web application for account registration,
authentication, simulated transfers, transaction history, and security monitoring.
It uses SQLite as its relational database and includes password hashing, session
validation, access controls, parameterized SQL, risk scoring, and transaction
atomicity. Its balances and transfers are simulated: it is not connected to a bank,
payment network, or settlement system and is not suitable for real customer data or
funds.

## 1. Introduction

### 1.1 Problem statement

Web-based account and payment systems must protect credentials, restrict access to
account data, validate payment instructions, and maintain consistent transaction
records. This project demonstrates these concerns in a local educational application.

### 1.2 Objectives

- Demonstrate account registration, bcrypt password verification, login, logout, and
  protected dashboard access.
- Validate transfer recipients and amounts, check available funds, and record
  transfers and ledger entries atomically.
- Apply server-side validation, parameterized SQL, CSRF protection, and role checks.
- Demonstrate behavior-based risk scoring, an AVL balance index, and graph traversal
  over access-event sequences.
- Provide administrator views for account controls, risk events, and transfer
  activity.

### 1.3 Scope and limitations

The current implementation is a **SQLite prototype**, not a production banking
system. It does not integrate with a bank or payment processor, and it does not
provide a MySQL adapter, distributed transaction infrastructure, a regulated fraud
model, or a production operational environment. The interface uses project CSS and
HTML templates; it is not currently implemented with Tailwind CSS. Claims in this
report describe the current code, not a hypothetical deployment.

## 2. System Architecture

### 2.1 Three-tier architecture

```text
┌───────────────────────────────────────────────────────────────┐
│ Presentation tier                                             │
│ Jinja HTML templates · CSS · browser JavaScript               │
│ Login/register · dashboard · profile · admin and risk views   │
└───────────────────────────────┬───────────────────────────────┘
                                │ HTTP requests + CSRF token
┌───────────────────────────────▼───────────────────────────────┐
│ Application tier                                               │
│ Flask routes · authorization · validation · risk assessment    │
│ Password/session services · transfer workflow · AVL / graph   │
└───────────────────────────────┬───────────────────────────────┘
                                │ parameterized SQL
┌───────────────────────────────▼───────────────────────────────┐
│ Data tier                                                      │
│ SQLite: users · sessions · transfers · ledger · risk · audit  │
└───────────────────────────────────────────────────────────────┘
```

**Presentation tier.** Browser forms collect user input and call Flask endpoints.
Jinja renders server-side pages, and dynamic values are escaped by default. The
JavaScript enhances form submission and interface behavior; it is not an
authorization boundary.

**Application tier.** Flask validates input, authenticates users, checks permissions,
evaluates risk, and coordinates database operations. The AVL index and access graph
are demonstrations maintained by application code; SQLite remains the durable
source of truth.

**Data tier.** SQLite stores account records, hashed session tokens, transfers,
double-entry-style ledger entries, risk events, access events, and audit data.
Foreign keys and constraints protect data relationships and ranges. SQLite write
transactions use explicit transaction handling.

### 2.2 Important request flows

#### Login

1. Browser submits username, password, device identifier, and CSRF token.
2. Flask looks up the account using bound SQL parameters and verifies the password
   hash.
3. Failed attempts update throttling and lockout state. Successful credentials are
    evaluated by the risk engine. Username- and network-scoped rate limits are
    independent, so changing IP alone does not bypass per-account throttling.
4. A medium-risk attempt requires a step-up challenge; high-risk attempts are
   blocked and recorded.
5. On successful verification, the server creates a random session token, stores its
   hash in SQLite, and places the token in the signed Flask session cookie.
6. Login attempts store keyed hashes of username, IP, and device identifiers rather
    than the raw IP/device values. The admin dashboard presents recent outcomes and
    shortened fingerprints for investigation.

#### Transfer

1. Flask authenticates the database-backed session and validates CSRF, amount,
   recipient, and request idempotency key.
2. Risk controls and the required Payment Password/MFA checks are applied.
3. The transfer service starts an immediate SQLite transaction, rechecks sender and
   recipient records, and conditionally debits the sender.
4. The service credits the recipient and writes the transfer, ledger rows, and audit
   event within the same transaction.
5. Any exception rolls back the transaction. Repeated requests with the same
   idempotency key and same details return the original receipt; conflicting reuse is
   rejected.

## 3. Backend Implementation

### 3.1 Source-code map

The complete runnable project code is already in the project directory:

| File | Responsibility |
| --- | --- |
| [`app.py`](./app.py) | Flask routes, login/session flows, role checks, risk gating, transfers, statements, and admin views |
| [`database.py`](./database.py) | SQLite schema, incremental schema updates, connection and transaction helpers |
| [`security.py`](./security.py) | bcrypt password hashing, password verification, encryption, sanitization, token hashing, and Payment Password verification |
| [`config.py`](./config.py) | Application configuration, development/production environment validation, key loading |
| [`risk_engine.py`](./risk_engine.py) | Decision Tree/KNN classifier, numeric scoring, and low/medium/high action selection |
| [`mfa_security.py`](./mfa_security.py) | TOTP validation, provisioning, and one-use recovery-code hashing |
| [`audit_chain.py`](./audit_chain.py) | HMAC-linked audit writes and chain verification |
| [`avl_tree.py`](./avl_tree.py) | AVL tree used as an in-memory account-balance index |
| [`graph_analyzer.py`](./graph_analyzer.py) | BFS/DFS and modeled suspicious access-path analysis |
| [`statement_pdf.py`](./statement_pdf.py) | In-memory generation of account-scoped PDF statements |
| [`templates/`](./templates/) and [`static/`](./static/) | HTML, CSS, and browser JavaScript |
| [`tests/test_security_integrity.py`](./tests/test_security_integrity.py) | Automated feature and security regression tests |

The code is separated into modules and uses function docstrings for the key security
and data-handling helpers. For an academic submission, cite the relevant functions
from these files rather than pasting a second, divergent copy of the backend into this
report.

### 3.2 Authentication and sessions

- Passwords are hashed and verified with bcrypt in `security.py`; plaintext passwords
  are not stored.
- Login queries use bound SQL parameters. Three consecutive incorrect passwords lock
  the account until administrator action. Separate username and IP fingerprints
  throttle attempts, and login velocity is counted over a five-minute window.
- Each account has a persisted `customer` or `admin` role. Admin routes require both
  the `admin` role and the configured administrator username; a username setting
  alone does not grant the database role.
- Session tokens are random and their hashes are stored in the `sessions` table.
  Protected requests validate the session against the database.
- Session cookies use HTTP-only and SameSite configuration. Production configuration
  enables the Secure cookie flag and requires deployment keys.
- CSRF tokens are checked on state-changing API requests.
- TOTP MFA and one-use recovery codes are available for enrolled users. High-value
  transfers additionally require the configured step-up checks.

**Important distinction:** the application uses Flask sessions backed by a
database-validated random bearer token; it does not use JWTs.

### 3.3 Transfer validation and atomicity

The `/api/transfer` route validates input and permission before invoking the transfer
service. The database helper begins an immediate transaction for writes. The service
conditionally debits with a balance predicate, credits the recipient, inserts the
transfer record and both ledger entries, and records the audit event before commit.
The transaction helper rolls back and re-raises errors rather than returning a
success-shaped fallback.

Amounts are stored as integer cents to avoid floating-point arithmetic for balances.
Idempotency keys prevent retries from applying the same transfer twice. The
`transfers` and `ledger_entries` records are demonstration bookkeeping only; they do
not represent settlement through a financial institution.

### 3.4 Database model summary

| Table | Purpose |
| --- | --- |
| `users` | Identity/profile data, bcrypt password verifier, persisted role, integer-cent balance, login lockout state, transfer controls, and MFA state |
| `sessions` | Hashed random session tokens, expiry, and revocation state |
| `login_events` / `known_devices` | Login time/location and pseudonymous device-history signals |
| `login_attempts` | Outcomes, risk decisions, and keyed username/IP/device fingerprints |
| `login_challenges` | Expiring login step-up challenges with attempt limits |
| `transfers` | Sender, recipient, amount in cents, encrypted new references, timestamp, and idempotency key |
| `ledger_entries` | Debit and credit records linked to each transfer |
| `risk_events` | Risk score, classification, action, reasons, and feature snapshot |
| `security_incidents` | High-risk actions linked to signed audit entries |
| `audit_chain` | Append-only HMAC-linked audit trail |
| `access_events` | Ordered event categories used for graph demonstrations |
| `mfa_recovery_codes` | One-use keyed hashes for account recovery |

`initialize_database()` creates new tables and adds missing columns to existing
SQLite databases. It is a lightweight SQLite schema evolution mechanism, not a
general-purpose migration framework. Back up the database before running code that
changes a real dataset.

## 4. Security Design Analysis

### 4.1 Password storage

The registration route calls the bcrypt helper before writing account data. Login
verifies the supplied password against the stored verifier. The password is not
returned to the browser or written to the user record in plaintext. The Payment
Password has a separate verifier and rate-limit/lockout handling.

### 4.2 SQL injection prevention

Database queries use SQLite placeholders (`?`) and pass values separately from SQL
text. User-supplied usernames, recipients, amounts, and identifiers are not
concatenated into query strings. Schema identifiers used in setup logic are
application-controlled, not user-controlled.

### 4.3 Input validation and XSS defense

Routes enforce length, format, and range checks before state changes. Free-text
reference/profile fields are sanitized using the existing helper. Jinja autoescapes
rendered values by default; client-side validation is supplementary only. Avoid
marking user-provided content as safe HTML.

### 4.4 Authentication, session protection, and CSRF

Successful login creates a random session token, stores its hash, and sets it in the
Flask session. The server checks token status and expiry for protected routes; logout
revokes the token. State-changing requests require a CSRF token. Cookie settings
include HTTP-only and SameSite protections, with Secure enabled in production mode.

### 4.5 Authorization and account ownership

Protected routes require an authenticated account. Administrative endpoints perform
an administrator check using both a persisted role and the configured administrator
username. Customer queries are scoped to the authenticated user unless an explicitly
authorized admin route is used. Transfer-access controls and account unlock actions
are limited to the administrator.

The username is configured through `ADMIN_USERNAME`; on database initialization the
matching account is promoted and other administrator-role records are demoted.
Privileged role changes and deployment configuration must be protected. A real
deployment would still need stronger permission granularity, independently enforced
admin MFA, and an audited recovery process.

### 4.6 Atomic transfers and integrity

SQLite `BEGIN IMMEDIATE` transactions serialize write workflows. The debit is
conditional on the available balance, and related balance, transfer, ledger, and
audit writes commit together. An error rolls back the full transaction. This protects
the prototype from partial transfer updates within its SQLite database.

### 4.7 Behavioral risk engine

The risk engine considers features such as distance between observed login
locations, time interval, estimated travel speed, whether the device is new, login
velocity (successful logins in the five-minute window), and transfer amount relative to a baseline. It combines classifier output
with policy rules and applies these configured score bands:

- **Low:** score below `0.4`, allow.
- **Medium:** score from `0.4` through `0.75`, require step-up verification.
- **High:** score above `0.75`, block and record an incident.

The project models are trained on synthetic examples. Browser location and device
identifiers are untrusted signals and can be spoofed; the risk engine is an
educational demonstration, not a calibrated fraud-detection service.

The admin dashboard shows the latest login-attempt outcomes alongside the risk and
activity views. Only HMAC fingerprints are stored for IP/device correlation; they
are pseudonymous data, not anonymous data. New transfer reference notes use AES-GCM
encryption, while legacy plaintext references remain supported. Balances, amounts,
and other transfer metadata are not encrypted at rest by this feature.

### 4.8 MFA and recovery codes

Authenticator secrets are encrypted before storage. TOTP checks enforce a six-digit
token and record the accepted time counter to reject replay. Recovery codes are
random, returned once, stored as keyed hashes, and consumed on use. MFA configuration
and recovery procedures still require independent review before any real deployment.

### 4.9 Audit chain and incident logging

Sensitive events are linked to the previous audit entry and authenticated with an
HMAC derived from the application secret. SQLite triggers prevent update/delete
operations through normal SQL operations. Chain verification checks integrity and
linkage. This is tamper-evidence, not absolute immutability: an attacker controlling
the application host or signing key can subvert logging, and database triggers are
not a substitute for off-host protected audit storage.

### 4.10 AVL index and graph scanning

The AVL tree maps internal user IDs to integer-cent balances and maintains balanced
height for logarithmic search/update. SQLite remains authoritative; the in-memory
index is a data-structure demonstration and must be rebuilt after restart.

The access graph turns ordered event categories into directed edges. BFS and DFS
traverse the resulting graph and compare it with modeled suspicious paths. This
detects only patterns represented by the recorded events; it is not a complete
authorization monitor or intrusion-detection system.

## 5. User Interface and Screenshot Analysis

### 5.1 Evidence collection guidance

Capture screenshots from a local test database using synthetic accounts only. Do not
include real names, emails, phone numbers, account numbers, recovery codes, TOTP
secrets, session cookies, or other credentials. Redact identifiers before submitting
the report. Record the browser page, test setup, and expected behavior for each image.

Suggested screenshots:

1. Login and registration pages.
2. Customer dashboard with a simulated balance and transfer form.
3. Security/risk monitor showing sample risk events and access graph.
4. Admin dashboard showing locked-account controls and a simulated transfer ledger.
5. Profile MFA enrollment with the QR payload and recovery codes obscured.
6. Downloaded monthly statement with personal fields redacted.
7. A test result or database view demonstrating a committed transfer and its ledger
   entries; use synthetic values only.

### 5.2 Three-part screenshot explanation template

Repeat this section for every screenshot:

#### Screenshot [number]: [descriptive title]

**Reference**

- Figure number and caption:
- Page/route:
- Test scenario and synthetic account setup:
- Date captured and application version:

**Technical Observation**

- What controls, fields, messages, or data are visible?
- What request or server-side operation does this screen represent?
- Which backend route, template, database table, or helper is responsible?
- What was the expected result, and what was observed?
- Which sensitive details were redacted?

**Security Significance**

- Which security property does the screenshot illustrate?
- What server-side enforcement backs up the visible interface?
- What threat does the control reduce?
- What threat or limitation remains?
- How was the behavior tested independently of the screenshot?

### 5.3 Example analysis: transfer review

**Reference:** Figure [N], customer dashboard, test transfer between two synthetic
accounts.

**Technical Observation:** The page shows the recipient and amount inputs and a
Payment Password prompt. The browser submits a CSRF-protected request to
`/api/transfer`. The server validates the request, checks account permissions and
risk, then uses the transfer service to atomically update balances and ledger rows.

**Security Significance:** This demonstrates layered checks and user-facing review,
but the interface alone does not prove authorization or balance correctness. Evidence
should include the corresponding API test and confirmation that a failed transfer
does not alter either balance or the ledger.

### 5.4 Example analysis: risk dashboard

**Reference:** Figure [N], security monitor using a synthetic new-device or unusual
transfer scenario.

**Technical Observation:** The page displays recorded risk decisions and graph
traversal output generated from stored events.

**Security Significance:** The screen demonstrates monitoring and explainable
signals. It does not establish that the model generalizes to real fraud; report the
synthetic training data and spoofable browser signals as limitations.

### 5.5 Example analysis: administrator controls

**Reference:** Figure [N], administrator dashboard using test accounts.

**Technical Observation:** The dashboard lists administrative account/transfer
controls and recent activity. The corresponding routes enforce the server-side
administrator check.

**Security Significance:** Server-side authorization prevents relying on hidden
buttons as access control. The current administrator identity configuration is
suitable only for this educational prototype and should be replaced by a proper
role/permission system before any deployment.

## 6. Testing and Evaluation

Run the existing suite from the project directory:

```bash
source venv/bin/activate
python -m unittest discover -s tests -v
```

The tests cover authentication/security behaviors, transfer atomicity and
idempotency, schema updates, MFA, statement privacy, audit-chain behavior, risk
scoring, and graph/AVL helpers. Include test output in the report, but do not describe
passing unit tests as proof of production security. Supplement them with manual
negative tests and a review of every state-changing route.

### 6.1 Evaluation table

| Requirement | Evidence to include | Result |
| --- | --- | --- |
| Password hashes, not plaintext | Registration/login tests and stored verifier format | [Complete after running tests] |
| Login lockout and logout | Failed-login, lockout, and session-revocation tests | [Complete after running tests] |
| Account-scoped dashboard/history | Route ownership tests with two synthetic users | [Complete after running tests] |
| SQL injection mitigation | Bound-parameter review and malicious-input tests | [Complete after running tests] |
| XSS defense | Template escaping and sanitized-field review | [Complete after running tests] |
| Role-based admin access | Authorized and unauthorized admin-route tests | [Complete after running tests] |
| Atomic transfers | Success, insufficient-funds, rollback, and retry tests | [Complete after running tests] |
| Risk decisions | Low/medium/high threshold tests and incident inspection | [Complete after running tests] |
| AVL and graph behavior | Data-structure unit tests | [Complete after running tests] |

## 7. Production Readiness Gap Analysis

Do not call this code production-grade. Before handling real accounts or funds, a
separate engineering and security program would be required, including:

- Independent threat modeling, code review, and penetration testing.
- A maintained production database deployment with reviewed migrations, backups,
  disaster recovery, least-privilege database identities, and operational monitoring.
- A robust identity/role system, strong authenticator policy, secure recovery,
  rate-limits at the edge, and incident response.
- Secure secret/key management, rotation procedures, and off-host immutable audit
  storage.
- TLS termination, hardened deployment, dependency monitoring, privacy and data
  retention controls, and jurisdiction-specific compliance review.
- Fraud model governance, representative authorized data, calibration, bias analysis,
  false-positive/false-negative review, and human escalation procedures.
- Integration with a regulated payment processor and reconciliation controls if
  actual transfers are ever in scope.

## 8. Conclusion

The project demonstrates how a Flask application can combine credential handling,
server-side authorization, transactional balance updates, behavioral risk checks,
and audit mechanisms. Its principal educational value is the integration and testing
of these controls in a simulated environment. The implementation must remain a
course-project prototype unless and until the production-readiness gaps above are
addressed and independently validated.

## Appendix A: Run the application

From the project directory:

```bash
source venv/bin/activate
pip install -r requirements.txt
flask --app app run --host 127.0.0.1 --port 5001
```

Open `http://127.0.0.1:5001`. Use synthetic practice accounts only.
