# ArvanCloud Telegram DNS Admin Bot

A private, guided Telegram bot for administering ArvanCloud CDN DNS records. It uses
`pyTelegramBotAPI`'s asynchronous `telebot.AsyncTeleBot` and the typed
[`arvancld`](https://github.com/faridrasidov/arvancld) SDK.

The bot lists CDN domains and supports DNS record listing, exact-name search, type filters,
creation, editing, cloud-proxy toggling, and deletion. Every DNS mutation has a single-use,
five-minute confirmation screen.

## Security model

- One ArvanCloud account is configured on the server; credentials are never entered in Telegram.
- Only numeric Telegram user IDs in `TELEGRAM_ADMIN_IDS` are accepted.
- Only private chats are accepted. Group and channel updates are rejected.
- When ArvanCloud requires TOTP, the first allowlisted administrator to open `/auth` owns the
  prompt for five minutes. The six-digit message is deleted immediately on a best-effort basis,
  submitted once, and never stored or logged. Telegram delivery and deletion are not a substitute
  for protecting the administrator's Telegram account and device.
- The saved ArvanCloud session contains bearer and refresh tokens in plaintext. Keep the `data/`
  directory private, backed up only through an encrypted mechanism, and never commit it.
- Logs contain actor IDs, opaque authentication attempt IDs, challenge revisions, actions,
  domains, record IDs, statuses, request IDs, and bounded response metadata. They do not contain
  passwords, OTP values, tokens, flow tokens, session contents, raw provider bodies/messages, or
  DNS values.
- A timed-out mutation is never retried automatically because its server-side outcome may be
  unknown. Refresh the record list before manually trying again.

## Supported DNS value input

| Type | Guided value format |
| --- | --- |
| `A` | One IPv4 address per line |
| `AAAA` | One IPv6 address per line |
| `ANAME` | `location` |
| `CNAME` | `host` |
| `NS` | `host` |
| `MX` | `host priority` |
| `SRV` | `target port weight priority` |
| `TXT` | Full text content |
| `PTR` | `domain` |
| `CAA` | `tag value` |
| `TLSA` | `usage selector matching_type certificate` |

Edits preserve ArvanCloud-specific fields that are not shown by the basic UI. For A and AAAA
records, unchanged IP targets keep their existing port, weight, and country metadata. Changing a
record type replaces incompatible value metadata and resets cloud mode to off.

## Configuration

Requires Python 3.10 or newer. Copy the example and fill in real values:

```powershell
Copy-Item .env.example .env
```

```dotenv
TELEGRAM_BOT_TOKEN=123456789:bot-token-from-BotFather
TELEGRAM_ADMIN_IDS=123456789,987654321
ARVANCLD_EMAIL=admin@example.com
ARVANCLD_PASSWORD=account-password
ARVANCLD_SESSION_PATH=data/arvancld-session.json
LOG_LEVEL=INFO
```

Create the bot token with [@BotFather](https://t.me/BotFather). Use numeric Telegram user IDs, not
usernames; forwarding one of your messages to an ID-inspection bot is a common way to discover it.
Treat third-party ID bots as untrusted and do not send them secrets.

The SDK dependency is pinned to the published and verified Git commit
`19f8b49b993bbec935f7cd61bbb65ff9bcb1982f` for reproducible installs, typed TOTP support, and
secret-safe API error diagnostics.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m arvancld_telegram
```

When upgrading an existing virtual environment, recreate it or force-reinstall the pinned
`arvancld` archive. Multiple SDK commits currently identify as version `0.1.0`, so pip may
otherwise retain an already-installed build.

The installed console command is equivalent:

```powershell
.\.venv\Scripts\arvancld-telegram.exe
```

On startup the bot loads its saved session. Missing, invalid, or expired sessions trigger one
account login and an atomic session save. If that login requires TOTP, the bot starts polling in a
restricted `OTP required` state and best-effort notifies the configured administrator chat IDs.
Telegram may reject a notification until that user has opened the bot at least once; `/auth` is
always the fallback.

A later `401` or `403` triggers one token refresh; a rejected refresh triggers one password login.
If this fallback reaches TOTP, the active DNS operation stops and is never resumed automatically.
After authentication, repeat the read operation or rebuild and reconfirm the mutation. Login,
refresh, OTP submission, and DNS mutations are otherwise not retried.

## Run with Docker Compose

Create the bind-mounted directory before first launch. On Linux, make it writable by container UID
`10001`; Windows Docker Desktop normally manages this automatically.

```bash
mkdir -p data
sudo chown 10001:10001 data
docker compose build --no-cache --pull
docker compose up -d
docker compose logs -f bot
```

The multi-stage build clones the SDK repository at `ARVANCLD_GIT_REF`, verifies that
`git rev-parse HEAD` exactly matches the 40-character SHA, builds wheels, and installs only those
wheels in the non-root runtime image. Git and both source histories are absent from the final
image. Changing the SHA invalidates the SDK checkout/build layer. No container port is published
because Telegram updates are received with long polling.

Inspect the baked SDK revision without printing any environment secrets:

```bash
SDK_IMAGE=$(docker compose images -q bot)
docker image inspect "$SDK_IMAGE" \
  --format '{{ index .Config.Labels "io.github.faridrasidov.arvancld.revision" }}'
docker compose logs bot | grep "arvancld sdk version="
```

The startup log reports the installed package version, exact SHA, module location, and whether
`submit_totp()` exists.

## Bot commands

- `/start` or `/domains` — list domains and open DNS administration.
- `/auth` — claim, complete, or restart interactive ArvanCloud login.
- `/status` — validate ArvanCloud access and show the domain count.
- `/help` — show commands and record types.
- `/cancel` — cancel the current input or confirmation.

Domain and record pages contain eight items and provide previous/next navigation, refresh,
exact-name search, record-type filtering, and back actions. Protected provider records are visible
but read-only. Before updating, toggling, or deleting, the bot reloads the record and refuses the
change if its `updated_at` value no longer matches the selected snapshot.

When authentication is incomplete, `/status` reports `OTP required`, `authenticating`, or
`unavailable` without attempting a CDN request. `/cancel` releases an owned OTP prompt; the next
`/auth` starts a fresh password-login challenge. An OTP request with a network-uncertain result is
not retried and must also be restarted with `/auth`.

## OTP diagnostics

Set `LOG_LEVEL=DEBUG` in `.env`, rebuild, and reproduce once through the normal Telegram `/auth`
flow. Do not run a separate login command. The initial Telegram text “ArvanCloud OTP required” and
the `totp_required` log mean that the challenge started; they do not mean the submitted code was
rejected.

A successful attempt has this safe correlated sequence (other HTTP library debug lines may appear
between stages):

```text
event=password_login_started attempt_id=...
event=totp_required attempt_id=... challenge_revision=...
event=totp_claimed attempt_id=... challenge_revision=... actor_id=...
event=telegram_otp_received attempt_id=... challenge_revision=... actor_id=...
event=telegram_otp_deleted attempt_id=... challenge_revision=... actor_id=...
event=telegram_otp_format_accepted attempt_id=... challenge_revision=... actor_id=...
event=totp_sdk_submission_started attempt_id=... challenge_revision=... actor_id=...
event=totp_sdk_submission_accepted attempt_id=... challenge_revision=... actor_id=...
event=session_save_started attempt_id=... challenge_revision=...
event=session_saved attempt_id=... challenge_revision=...
event=cdn_validation_started attempt_id=... challenge_revision=...
event=cdn_validation_completed attempt_id=... challenge_revision=...
```

An API rejection logs `totp_sdk_submission_rejected` with HTTP status, request ID, and elapsed
time. At DEBUG it adds only content type, body byte count, top-level field names, and validation
field paths/types. A provider `200` followed by `totp_sdk_submission_invalid_response` identifies
a successful HTTP exchange whose response did not match the SDK contract. A deletion failure does
not stop submission. A `400`, `401`, `403`, or `422` is submitted exactly once and keeps the
challenge usable; a network-uncertain or invalid-success-response outcome requires a fresh
`/auth`.

When asking for help, share only the relevant lines for one `attempt_id` and its provider request
ID. Do not share `.env`, the session file, Telegram message text, or raw provider bodies.

## Validation

Automated validation never contacts Telegram or ArvanCloud:

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\python.exe -m pytest
docker build --tag arvancld-telegram:test .
```

After deployment, perform read-only checks with `/status`, `/domains`, record pagination, search,
and filters. If live mutation validation is needed, create a clearly disposable DNS record, test
edit/cloud/delete on only that record, and verify the final state in the ArvanCloud panel.

## V1 boundary

The underlying SDK lists domains but does not implement domain creation, editing, or deletion.
This bot therefore performs CRUD on DNS records only. Multi-account login, group use, webhooks,
bulk zone import/export, DDNS scheduling, persistent wizard state, and localization are outside V1.
