# CyberTeller

Crypto invoicing and payment processor.

## Features

- **Invoice API** – create invoices via REST (`POST /api/invoices`) with amount, currency, description, and customer details
- **Unique payment addresses** – each invoice gets a fresh HD-wallet derived address per chain (no address reuse)
- **4 supported blockchains** – Ethereum, Tron, Solana, TON
- **Crypto & stablecoins** – ETH, TRX, SOL, TON native coins + USDT / USDC on every supported chain
- **Payment page** – customer-facing page with QR codes and copy-address buttons, auto-refreshes via HTMX every 15 s
- **Payment status tracking** – `paid` / `underpaid` / `overpaid` / `expired`
- **Webhook endpoint** – `POST /api/payment/notify` for blockchain monitoring integrations
- **Admin panel** – dashboard, invoice detail view, live YAML config editor
- **YAML config** – editable at runtime via admin UI (chains, tokens, expiry, tolerance thresholds, wallet seed)

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.24, `net/http` + chi router |
| Frontend | HTMX, vanilla JS |
| Database | SQLite (CGO-free via modernc.org/sqlite) |
| HD wallet | BIP-39/BIP-32 (secp256k1) · SLIP-0010 (ed25519) |
| QR codes | github.com/skip2/go-qrcode |

## Quick Start

```bash
# 1. Clone and install dependencies
git clone https://github.com/hrbrlife/cyberteller
cd cyberteller
go mod download

# 2. Edit config.yaml – set your wallet mnemonic and admin password hash
#    Generate a bcrypt hash:  htpasswd -bnBC 10 "" yourpassword | tr -d ':\n'

# 3. Run
go run .
# Server starts on http://0.0.0.0:8080
```

Environment variables (all optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_PATH` | `config.yaml` | Path to config file |
| `DB_PATH` | `cyberteller.db` | Path to SQLite database |
| `BASE_URL` | `http://localhost:8080` | Public URL used in payment links |

## API

### Create Invoice

```http
POST /api/invoices
Content-Type: application/json

{
  "amount": "99.99",
  "currency": "USD",
  "description": "Order #42",
  "customer_name": "Alice",
  "customer_email": "alice@example.com"
}
```

Response `201 Created`:
```json
{
  "id": "...",
  "payment_link": "http://localhost:8080/pay/abc12345",
  "expires_at": "2026-01-01T12:00:00Z",
  "status": "pending"
}
```

### Payment Webhook

Called by your blockchain monitoring service when a payment is detected:

```http
POST /api/payment/notify
Content-Type: application/x-www-form-urlencoded

invoice_id=...&chain=ethereum&token=USDT&address=0x...&tx_hash=0x...&amount=99.99
```

## Admin Panel

Navigate to `http://localhost:8080/admin` (HTTP Basic Auth).

Default credentials: `admin` / `changeme` — **change before production** by updating `password_hash` in `config.yaml`.

## Security Notes

- Replace the default wallet mnemonic in `config.yaml` with your own before using with real funds
- The mnemonic in `config.yaml` is used to derive all payment addresses — back it up securely
- Change the admin password hash before deploying
- The payment notification endpoint (`/api/payment/notify`) should be firewall-restricted to your blockchain monitoring service in production

![Payment page screenshot](https://github.com/user-attachments/assets/29088b6d-ac48-401a-b899-14c326fe18d0)
