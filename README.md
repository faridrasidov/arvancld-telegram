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
- The saved ArvanCloud session contains bearer and refresh tokens in plaintext. Keep the `data/`
  directory private, backed up only through an encrypted mechanism, and never commit it.
- Logs contain actor IDs, actions, domains, record IDs, statuses, and request IDs. They do not
  contain passwords, tokens, session contents, or DNS values.
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

The SDK dependency is pinned to the verified Git commit
`c71a3fee9597adc98ce1b9c2044254932b7b1e68` for reproducible installs.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m arvancld_telegram
```

The installed console command is equivalent:

```powershell
.\.venv\Scripts\arvancld-telegram.exe
```

On startup the bot loads its saved session. Missing, invalid, or expired sessions trigger one
account login and an atomic session save. A later `401` or `403` triggers one token refresh; a
rejected refresh triggers one password login. Login, refresh, and DNS mutations are otherwise not
retried.

## Run with Docker Compose

Create the bind-mounted directory before first launch. On Linux, make it writable by container UID
`10001`; Windows Docker Desktop normally manages this automatically.

```bash
mkdir -p data
sudo chown 10001:10001 data
docker compose up --build -d
docker compose logs -f bot
```

No container port is published because Telegram updates are received with long polling.

## Bot commands

- `/start` or `/domains` — list domains and open DNS administration.
- `/status` — validate ArvanCloud access and show the domain count.
- `/help` — show commands and record types.
- `/cancel` — cancel the current input or confirmation.

Domain and record pages contain eight items and provide previous/next navigation, refresh,
exact-name search, record-type filtering, and back actions. Protected provider records are visible
but read-only. Before updating, toggling, or deleting, the bot reloads the record and refuses the
change if its `updated_at` value no longer matches the selected snapshot.

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
