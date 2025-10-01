# FortiGate Log Backup Suite — S3 + SQLite + Email + API

Production‑ready toolkit to **upload FortiGate `.gz` logs to S3**, record each upload in **SQLite**, and publish a **read‑only FastAPI** to query the records (good for Grafana/API Gateway integrations).

This repository includes:

1) `backup_fg.py` — uploader/validator that:
   - computes SHA256;
   - uploads to S3 (adds object metadata `sha256=<hash>`);
   - stores **only the base S3 URL** in SQLite (no presign);
   - optionally deletes local files after verified;
   - optionally emails a summary including **only the last DB entry**.

2) `backup_api.py` — FastAPI that **reads the same SQLite file** and exposes the records with **Bearer token** auth, plus `/health` for probes.

---

## Architecture

```
.gz files  -->  backup_fg.py  -->  SQLite (/var/lib/backup_fg/backup_records.db)  -->  backup_api.py
                                  |                                             \
                                  +--> S3 object (with sha256 metadata)          +--> Dashboards (e.g., Grafana JSON API)
```

---

## Requirements

- Python 3.9+
- `boto3`, `botocore`, `fastapi`, `uvicorn[standard]`
- AWS (or S3‑compatible) credentials/profile
- SMTP account (e.g., Gmail **App Password**) for notifications

```bash
python -m venv /opt/backup
/opt/backup/bin/pip install -U pip boto3 botocore fastapi uvicorn[standard]
```

---

## SQLite schema

Created automatically by `backup_fg.py`:

```sql
CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  s3_url TEXT,          -- base URL only (no presign)
  sha256 TEXT,
  uploaded_at TEXT,     -- UTC ISO8601 with 'Z'
  backup_date TEXT,     -- YYYY-MM-DD
  deleted_local INTEGER DEFAULT 0,
  status TEXT           -- uploaded | skipped_exists | failed_*
);
CREATE INDEX IF NOT EXISTS idx_backups_uploaded_at ON backups(uploaded_at);
```

---

## Environment files (systemd friendly)

> **Path**: `/etc/default/backup_api`  
> **Mode**: `0600` (contains secrets/tokens)

```bash
# Environment file for backup_api systemd unit
APP_TOKENS="***redacted***,***redacted***"
DB_PATH=/var/lib/backup_fg/backup_records.db
```

> **Path**: `/etc/default/backup_fg`  
> **Mode**: `0600`

```bash
# Email (SMTP)
GMAIL_USER="ops@example.org"
GMAIL_APP_PASSWORD="***app password***"

# Optional method/host/port (defaults are smtp.gmail.com:587 for STARTTLS)
EMAIL_METHOD="starttls"         # or "smtps"
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"

# Optional: recipients (the unit passes this var as --notify-email)
NOTIFY_EMAIL="noc@example.org,sec@example.org"
EMAIL_DRY_RUN="0"

# Required basics: source dir and bucket
DIR=/var/log/fortinet
BUCKET=backup-logs-conf

# Optional behavior
DELETE_AFTER=true
WORKERS=4
# Do NOT set custom S3 endpoint here if using AWS CLI profiles. Prefer ~/.aws/config
```

> Keep credentials out of Git. Use proper file permissions.

---

## Systemd units (as deployed)

### API service

`/etc/systemd/system/backup_api.service`
```ini
[Unit]
Description=Backup FG API (FastAPI via uvicorn)
After=network.target

[Service]
Type=simple
User=backup
Group=backup
EnvironmentFile=/etc/default/backup_api
WorkingDirectory=/usr/local/bin
# Use the venv uvicorn binary
ExecStart=/opt/backup/bin/uvicorn backup_api:app --host 127.0.0.1 --port 8080
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Uploader service + timer

`/etc/systemd/system/backup_fg.service`
```ini
[Unit]
Description=Backup FG (upload .gz to S3) - one-shot via venv python
After=network.target

[Service]
Type=oneshot
User=root
Group=root
EnvironmentFile=/etc/default/backup_fg
# Run with the venv's python to isolate environment
ExecStart=/opt/backup/bin/python3 /usr/local/bin/backup_fg.py \
  --delete \
  --dir ${DIR} \
  --bucket ${BUCKET} \
  --notify-email ${NOTIFY_EMAIL} \
  --email-method ${EMAIL_METHOD} \
  --smtp-host ${SMTP_HOST} \
  --smtp-port ${SMTP_PORT}
TimeoutStartSec=1h
Nice=10

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/backup_fg.timer`
```ini
[Unit]
Description=Timer to run backup_fg daily at 01:00

[Timer]
OnCalendar=*-*-* 01:00:00
Persistent=true
Unit=backup_fg.service

[Install]
WantedBy=timers.target
```

Enable everything:

```bash
systemctl daemon-reload
systemctl enable --now backup_api.service
systemctl enable --now backup_fg.timer
```

---

## Running manually (quick tests)

```bash
# API (dev)
export DB_PATH=/var/lib/backup_fg/backup_records.db
export APP_TOKENS="token1,token2"
/opt/backup/bin/uvicorn backup_api:app --host 0.0.0.0 --port 8080

# Health (no auth)
curl -sS http://127.0.0.1:8080/health

# List backups (Bearer auth)
curl -sS -H "Authorization: Bearer token1" http://127.0.0.1:8080/backups | jq

# Uploader (dry-run)
/opt/backup/bin/python3 /usr/local/bin/backup_fg.py --dir /var/log/fortinet --bucket backup-logs-conf --dry-run

# Uploader (real)
/opt/backup/bin/python3 /usr/local/bin/backup_fg.py --dir /var/log/fortinet --bucket backup-logs-conf --delete --workers 4
```

---

## S3 notes

- Uploader uses `head_object` to verify and compare the `sha256` metadata after upload.
- For existing objects, it **skips re-upload** but still writes a `skipped_exists` row with the base `s3_url`.
- Confirm bucket access with: `aws s3 ls` (should list `backup-logs-conf`).

---

## Email summary behavior

- On **success** (no failures), the email contains **only the latest DB entry**.
- On **failure**, the email contains the error summary + latest DB entry if available.
- STARTTLS (587) or SMTPS (465) supported. Use App Passwords where applicable.

---

## Hardening & exposure

- API is bound to **127.0.0.1:8080** in the service. Expose it safely via a reverse proxy if needed.
- Example (HAProxy snippet):
```haproxy
frontend fg_api_in
  bind *:9000
  mode http
  acl is_health path -i /health
  default_backend fg_api_be

backend fg_api_be
  mode http
  option httpchk GET /health
  server api1 127.0.0.1:8080 check inter 5s fall 3 rise 2
```
- Keep `/etc/default/*` with `0600` and rotate `APP_TOKENS` periodically.

---

## Troubleshooting

- **`DB locked`**: each worker opens its own SQLite connection. If contention persists, increase `--workers` carefully or consider PostgreSQL later.
- **`failed_nometa`**: S3 object missing `sha256` metadata — check IAM and proxies.
- **401 on API**: confirm `Authorization: Bearer <token>` and that the token exists in `APP_TOKENS`.
- **Email not sent**: validate method/port, and use App Passwords for Gmail.

---

## Roadmap

- Pagination/filters on `/backups` (by date/status/filename).
- `/backups/last` endpoint.
- Optional presign service behind auth.
- Prometheus metrics for uploader and API.
---

## NGINX TLS reverse proxy (example)

> Your API listens on **127.0.0.1:8080**. This NGINX vhost terminates TLS on 443 and proxies to the local API.
> Replace certificate/key paths with the ones provisioned by certbot or your PKI.

`/etc/nginx/conf.d/apifg-bkp.praiaclube.org.br.conf`
```nginx

server {
    # escuta HTTP e redireciona para HTTPS
    listen 80;
    listen [::]:80;
    server_name apifg-bkp.example.com;

    # redirect all other to https
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name apifg-bkp.example.com;

  # certbot will inject correct paths after issuance; placeholders below
  ssl_certificate     /etc/nginx/ssl/example.com.crt;
  ssl_certificate_key /etc/nginx/ssl/example.com.key;
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:50m;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!aNULL:!eNULL:!MD5';

  # (optional) basic hardening headers
  add_header X-Frame-Options DENY;
  add_header X-Content-Type-Options nosniff;
  add_header Referrer-Policy no-referrer-when-downgrade;
  add_header Content-Security-Policy "default-src 'none'" always;

  # Proxy settings to backend (your app)
  client_max_body_size 100M;
  proxy_connect_timeout 10s;
  proxy_read_timeout 120s;
  proxy_send_timeout 60s;

  location / {
    proxy_pass http://127.0.0.1:8080/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    # keep large headers if needed
    proxy_buffering off;
  }

  # optional: health endpoint proxied
  location /health {
    proxy_pass http://127.0.0.1:8080/health;
  }
}
```

Reload and enable NGINX:
```bash
nginx -t && systemctl reload nginx
systemctl enable --now nginx
```

**Firewall (Oracle/RHEL-based):**
```bash
firewall-cmd --add-service=https --permanent
firewall-cmd --reload
```

**SELinux (if enforcing):**
```bash
setsebool -P httpd_can_network_connect 1   # allow NGINX to reach 127.0.0.1:8080
```
