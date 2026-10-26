# Design and Implementation of a Secure Online Banking Login and Transfer System

FinBest is a **local digital banking interface prototype** for exploring secure web
application patterns. It uses synthetic balances and does not connect to a bank,
payment processor, or settlement network. It is not suitable for holding real customer
data or handling real money.

## 1. VS Code installation and running

Requirements: Python 3.10 or newer and VS Code with the Python extension.

1. Open the `secure-online-banking` folder in VS Code.
2. Open the integrated terminal and create an environment:

   ```bash
   python -m venv venv
   ```

3. Activate it:

   ```bash
   # macOS / Linux
   source venv/bin/activate

   # Windows PowerShell
   .\venv\Scripts\Activate.ps1
   ```

4. Install the dependencies and start the local server:

   ```bash
   pip install -r requirements.txt
   python app.py
   ```

5. Open `http://127.0.0.1:5001` in a browser. Create two practice profiles to test a
   transfer between them. Registration requires a six-digit Payment Password once;
   low-risk sign-in uses the account password, while a medium-risk sign-in asks for
   the Payment Password as a one-time step-up before creating a session. Every
   transfer requires it for authorization. Completed transfers show a printable receipt.

Sign-in and account creation have separate pages at `/login` and `/register`.
Each page links to the other; `/auth` redirects to the sign-in page for compatibility.

The existing account named `Xanuhas` is the default administrator. Admin sign-in opens
the dedicated dashboard at `/admin/dashboard`; it includes account unlock controls,
customer transfer blocking, a system-wide transfer ledger, recent login attempts,
risk events, and the risk threshold. Administrator access requires both the configured
username and its persisted `admin` role; configuring a username does not by itself
grant privileges.
To use another existing practice account as administrator, start the app with:

```bash
ADMIN_USERNAME=your_username python app.py
```

The admin can manually unlock accounts locked after three consecutive incorrect passwords,
or block/unblock a customer's outgoing transfers. Transfer blocks do not prevent sign-in or
incoming transfers. The risk threshold is 1–100 times the typical transfer (default 5) and
only controls risk flags; it does not bypass Payment Password or balance checks. Ensure the
configured administrator username belongs to the intended account.

Signed-in customers can view their own paginated ledger at `/transactions`; the route is
session-protected and filters ledger rows by the authenticated user ID. The customer
dashboard shows a shorter recent-activity list and links to the full history.

The homepage uses photographic backgrounds from Unsplash
([city architecture](https://images.unsplash.com/photo-1486406146926-c627a92ad1ab) and
[a point-of-sale payment](https://images.unsplash.com/photo-1556742049-0cfed4f6a45d)).
The “Easy by design” section also includes a separate customer-focused photo
([people collaborating on a laptop](https://images.unsplash.com/photo-1516321318423-f06f85e504b3)).
All images are stored in `static/images/`, so the site does not request images from a third-party service at runtime.

The profile picture and first name in the header link directly to Profile Settings.
Customers can update their phone number, login password, and profile photo there. A
Payment Password is created during registration and is not changeable from Profile
Settings. It is not requested on low-risk sign-ins; medium-risk sign-ins require an
exceptional step-up PIN challenge, which expires after five minutes and is single-use.
The theme preference is stored in browser local storage.

Payment Passwords are low-entropy secrets, not an equivalent substitute for a
hardware-backed authenticator or independently delivered second factor. This prototype
stores a salted, application-secret-protected verifier and temporarily locks Payment
Password authorization after three incorrect PIN attempts for 15 minutes. Login accounts
lock after three consecutive incorrect passwords and require administrator unlock.
Never reuse a real banking PIN. The application binds to loopback by default.

Failed login attempts are audited without retaining raw IP addresses or device IDs:
the database stores keyed HMAC fingerprints. Throttling uses separate username and
network fingerprints to resist simple IP rotation and username spraying, and an
account is locked after three consecutive incorrect passwords. Login-velocity scoring
uses a five-minute window; the admin dashboard shows recent outcomes with shortened
fingerprints for correlation.

Customers can enroll an authenticator in Profile Settings. Scan the displayed QR code,
confirm the current six-digit TOTP, and save the recovery codes shown once. The encrypted
TOTP secret is stored in SQLite; recovery codes are stored as keyed hashes and each code
can be used only once. Enabled MFA is required during sign-in and for transfers of
$1,000 or more. Those transfers also require the Payment Password. Use an unused recovery
code if the authenticator is unavailable; keep recovery codes separate from the account
password.

The shared risk engine returns a score from 0.0 to 1.0: scores below 0.4 are allowed,
scores from 0.4 through 0.75 require a step-up challenge, and scores above 0.75 are
blocked and recorded as security incidents. For transfers, step-up uses the Payment
Password; for sign-ins, customers without MFA use the Payment Password, while enrolled
customers use TOTP or a recovery code. The administrator can review risk and incident
records on the dashboard.

Customers can download a monthly PDF statement from the dashboard. It is generated in
memory, scoped to the signed-in account, and includes a keyed verification digest. The
admin dashboard also offers audit-chain verification. Sensitive operations are linked
in an append-only, HMAC-signed chain; keep `SECRET_KEY` stable and private because
changing it makes existing chain entries unverifiable. These controls provide
tamper-evidence, not protection against a compromised application host or signing key.
New transfer reference notes are AES-GCM encrypted in SQLite and decrypted only for
authorized application views. Existing legacy reference text is still readable, and
account balances and transfer amounts remain unencrypted in the database.

### Secure deployment settings (not real banking)

Setting `APP_ENV=production` requires all of the following environment variables:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | High-entropy Flask signing key |
| `ENCRYPTION_KEY` | 32-byte AES key encoded as URL-safe Base64 |
| `DATABASE_PATH` | Persistent SQLite database path (optional override) |
| `PUBLIC_BASE_URL` | Public HTTPS origin used by receipt verification QR codes |

`APP_ENV` accepts only `development` or `production`; any other value fails during
startup. Production startup also fails unless both `SECRET_KEY` and `ENCRYPTION_KEY`
are explicitly configured. Keep development keys confined to local practice data.

Create an encryption key without printing it into source control, for example with
`python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"`.
Store secrets in a secret manager or protected environment, back them up safely, and
do not rotate the encryption key without a migration plan. Production mode also sets
the session cookie's `Secure` flag; serve it only behind correctly configured HTTPS.

This prototype still requires a formal threat model, independent security review,
operational monitoring, data-retention and privacy controls, database backup/recovery,
deployment hardening, abuse controls at the edge, and applicable financial regulatory
approvals before any real-world use.

## 2. Three-tier architecture and sequence flow

```text
┌──────────────────────────────────────────────────────────────────┐
│ Presentation tier: Jinja templates, CSS, browser JavaScript       │
│ Forms · accessibility · client hints · CSRF token · fetch API     │
└───────────────────────────────┬──────────────────────────────────┘
                                │ HTTPS in a real deployment
┌───────────────────────────────▼──────────────────────────────────┐
│ Application tier: Flask routes and domain services                │
│ Validation · bcrypt · Payment PIN checks · risk engine             │
│ Transfer orchestration · graph scanner · AVL index                │
└───────────────────────────────┬──────────────────────────────────┘
                                │ parameterized SQL / transactions
┌───────────────────────────────▼──────────────────────────────────┐
│ Data tier: SQLite                                                 │
│ User records · encrypted identifiers · sessions · ledger · audit  │
└──────────────────────────────────────────────────────────────────┘
```

### Sign-in sequence

```text
Browser       Flask API             Risk service          SQLite
   │ POST credentials + CSRF │          │                   │
   ├────────────────────────>│ check failure lockout       │
   │                         ├────────────────────────────>│
   │                         │ verify PBKDF2 hash          │
   │                         │ score device/travel/velocity│
   │                         │                             │
   │                         │ high risk: block + log       │
   │<── medium-risk PIN ─────┤ create short-lived challenge │
   ├── PIN + CSRF ──────────>│ verify PIN / lockout         │
   │<── session cookie ──────┤ persist session after success│
```

### Transfer sequence

```text
Browser       Flask API             Risk engine          SQLite
   │ POST destination, amount, PIN, CSRF, idempotency key    │
   ├──────────────────────> check DB-backed session token ─>│
   │                       validate recipient and amount    │
   │                       ├──────────── assess pattern ────>│
   │                       │ verify PIN / enforce lockout   │ high: block
   │                       │                                 │
   │                       ├──── BEGIN IMMEDIATE ───────────>│
   │                       │ check funds; debit + credit     │
   │                       │ ledger + ref + idempotency key  │
   │                       │ audit event + COMMIT/ROLLBACK  │
   │<──────────────────────┴──── receipt + updated balance ─┤
```

The sender debit is conditional on sufficient funds and runs in the same SQLite
transaction as the recipient credit and ledger writes. An exception rolls back every
write in that transaction. Each submitted transfer carries a random idempotency key,
unique per sender. A retry with the same key and details returns the original transfer
and receipt; reusing the key with changed details is rejected. SQL values are bound as
parameters; user input is never interpolated into SQL statements. SQLite runs in WAL
mode with `synchronous=FULL`; each write transaction uses `BEGIN IMMEDIATE`, commits
on success, and rolls back before re-raising failures. Successful transfer audit events,
both ledger entries, and balance changes share that transaction.

### Automated regression checks

Run the standard-library test suite from the project directory:

```bash
python -m unittest discover -s tests -v
```

The suite uses a temporary SQLite database and verifies transfer replay protection,
idempotency-key conflicts, legacy-schema migration of role/lockout/reference/challenge
fields, insufficient-balance handling, commit and audit persistence, rollback after an
injected database failure, password hashing, three-attempt lockout across IP changes,
privacy-preserving login logs, admin-role enforcement, five-minute login velocity,
revoked-session rejection, SQL-like input handling, protected-route access, invalid
environment rejection, TOTP enrollment/replay protection, one-use recovery codes,
high-value transfer MFA, encrypted transfer references, PDF statement privacy,
audit-chain immutability, and risk/graph/AVL behavior. It is a regression suite for the
prototype, not a substitute for independent penetration testing, load testing, or
formal assurance.

## 3. ML feature engineering and classification

The feature vector is
`[distance_km, interval_hours, physical_speed_kmh, new_device, login_velocity,
amount_ratio]`.

* **Distance** is the Haversine great-circle distance between two browser locations,
  if the user explicitly grants location permission. Otherwise the feature is zero.
* **Time interval** is elapsed time between login records; physical speed is
  distance divided by interval. Client-provided coordinates are spoofable and only
  serve as a weak anomaly signal.
* **New device** indicates that the browser-generated device token is not enrolled.
  This token is a risk hint, not a hardware identity.
* **Login velocity** counts recent successful login events in a five-minute window.
* **Amount ratio** compares a transfer to the account's mean prior outgoing transfer;
  before the first transfer, opening demo balance is used as a baseline.

The app trains a small deterministic **Decision Tree** and standardized **K-Nearest
Neighbors (KNN)** classifier on synthetic examples at startup. Both classifiers'
probabilities and policy guardrails are normalized to a score from 0.0 to 1.0.
Scores below 0.4 are allowed; 0.4 through 0.75 require step-up verification; scores
above 0.75 are blocked. High-risk login and transfer attempts are recorded as signed
security incidents, and risk decisions are visible to the administrator. The
configurable transfer-amount ratio contributes to the score; it does not override the
score bands.
These models are illustrative and are not trained, calibrated, or tested for real
fraud detection. **Naive Bayes** is a useful alternative baseline: it estimates class
likelihoods from feature distributions, but
the independence assumption is often unrealistic for correlated speed, distance,
and interval features.

Login-risk decisions, transfer-risk flags, account audit events, and ordered access
resources are stored in SQLite. The Xanuhas dashboard shows recent risk decisions,
activity, and per-account BFS/DFS graph scans. A denied attempt to open the admin
dashboard is modeled as a suspicious access sequence. The AVL index is synchronized
with SQLite account balances at creation and after committed transfers; SQLite remains
the source of truth and transfer changes use `BEGIN IMMEDIATE` with rollback on failure.
On startup, `initialize_database()` creates the risk, access, login-attempt, and
challenge tables and adds missing role, lockout, risk-score, and encrypted-reference
columns to existing SQLite databases. This is an incremental compatibility migration,
not a replacement for a tested backup and schema-migration process.

### Training and validation CLI

Run the reproducible training/evaluation pipeline from the project directory:

```bash
python train_risk_model.py
```

By default, the script creates a seeded synthetic dataset, uses a stratified 80/20
train/validation split, and reports a confusion matrix plus macro precision, recall,
and F1-score for the Decision Tree, KNN, and combined maximum-severity predictions.
Use `--test-size 0.25` to change the held-out fraction or `--seed 7` to reproduce a
different split.

To evaluate authorized, de-identified labeled records instead, provide a CSV with
numeric columns `distance_km,interval_hours,physical_speed_kmh,new_device,login_velocity,amount_ratio,label`.
Labels must be `0` (LOW), `1` (MEDIUM), or `2` (HIGH), with at least ten records per
class:

```bash
python train_risk_model.py --csv /path/to/anonymized-risk-data.csv
```

Do not include names, account numbers, credentials, precise identifying location
history, or other personal information. The script evaluates a fresh model using the
same classifier factory as the application; it does not overwrite or automatically
promote the app's illustrative startup model. Synthetic or historical test metrics
are not evidence of real-world fraud detection. A production model requires a
representative, legally authorized dataset, leakage review, calibration, documented
operating thresholds, independent validation, and a controlled deployment process.

## 4. Graph theory and BFS/DFS

`AccessGraph` represents event categories as vertices and their observed directed
successive transitions as edges. BFS explores reachable event categories level by
level; DFS explores one path deeply before backtracking. The monitor checks the
modeled sequence `Login → Database → Admin → Files`. This prototype records only
login, database, and transfer categories, so it should not be interpreted as an
enterprise authorization monitor. A production implementation should derive events
from trusted server-side authorization decisions and alert on explicit privilege
boundaries, not user-controlled event names.

For `V` vertices and `E` edges, BFS and DFS each take `O(V + E)` time and `O(V)` extra
space. The monitor limits its stored event history query to the latest 500 records.

## 5. AVL tree complexity

The AVL tree indexes internal account IDs to balances in integer cents. It is used
for the data-structure demonstration and exposes only aggregate size and height to
the signed-in user's monitor; no other account balances are rendered. Single-key
search, insertion/update, and rotations are `O(log N)` because AVL height remains
`O(log N)`. An ordinary, unbalanced binary search tree may degrade to `O(N)` height
and search time for sorted insertions. The visualization index is in-memory and
reconstructed from SQLite; the database remains the authoritative balance store.

## 6. Security compliance audit (five core controls)

| Control | Implementation | Assessment and remaining limitation |
| --- | --- | --- |
| Password storage | bcrypt with a random salt and SHA-256 prehash for passwords of arbitrary supported length; plaintext is not persisted. Existing PBKDF2-HMAC-SHA256 hashes are verified and upgraded to bcrypt on successful sign-in. | Good demonstration baseline. Production should benchmark cost settings and consider a reviewed memory-hard Argon2id deployment after migration planning. |
| Sensitive identifiers | National ID is encrypted with AES-256-GCM and a random nonce; email/phone remain plaintext in this local prototype. PIN verifiers use a random salt and application-secret HMAC. | A six-digit PIN is low entropy and is not equivalent to independent MFA. Real use needs field-level privacy review, key rotation, retention controls, and encryption/access policy for all PII. |
| Injection and output safety | SQL uses bound parameters; Jinja auto-escapes templates; reference notes are stripped to plain text; CSRF token guards state-changing routes. | Keep HTML escaping enabled. CSRF/session protections require HTTPS and correct reverse-proxy configuration in deployment. |
| Authentication abuse and sessions | Three consecutive password or PIN failures trigger account lockout; database-backed random bearer sessions expire after 30 minutes and can be revoked. | The SQLite throttle is not distributed across independent databases; production needs edge-level controls, monitoring, stronger MFA, and reviewed recovery policies. |
| Transfer integrity and anomaly policy | Parameterized queries, `BEGIN IMMEDIATE`, conditional debit, paired ledger writes, rollback, per-sender idempotency keys, PIN lockout, risk blocking, and receipt references. | No external payment settlement, dispute handling, dual approval, regulatory controls, independent penetration test, or validated fraud model is included. |

### Additional design notes

* All balances use integer cents to avoid floating-point currency arithmetic.
* A per-sender idempotency key prevents duplicate ledger transfers when a client retries
  after an uncertain network response. The same key cannot be reused for changed details.
* The server rejects oversized requests and validates inputs independently of browser
  constraints.
* The session token is random, stored only as a SHA-256 digest in SQLite, and checked
  against its user, revocation status, and expiry before protected operations.
* Responses include a restrictive Content Security Policy, MIME-sniffing and framing
  protections, a referrer policy, and a permissions policy. HSTS is emitted only for
  secure requests in production; configure the HTTPS terminator and any trusted proxy
  correctly before deployment.
* Receipt verification QR codes contain an opaque random reference and disclose only
  transaction status, amount, and timestamp. Set `PUBLIC_BASE_URL` to the deployed
  HTTPS origin when hosting outside localhost.
* Precise geolocation is optional and requested only after the user checks the
  consent box. Denying it does not block sign-in.

## Project layout

```text
secure-online-banking/
├── app.py
├── avl_tree.py
├── config.py
├── database.py
├── graph_analyzer.py
├── risk_engine.py
├── security.py
├── train_risk_model.py
├── requirements.txt
├── README.md
├── tests/
│   └── test_security_integrity.py
├── static/
│   ├── css/style.css
│   └── js/main.js
└── templates/
    ├── auth.html
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── profile.html
    ├── receipt_verify.html
    └── risk_monitor.html
```
