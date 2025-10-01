#!/usr/bin/env python3
"""
backup_fg.py - Adjusted version: stores only the base URL (without presign) in SQLite.
Added: email sending functions (STARTTLS and SMTPS), send test,
and a notification that includes **only the last entry** from SQLite when the run
finishes successfully; in case of failure, it sends an error message with a summary and
the last entry (if available).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, date
from typing import Optional, Iterable, Dict, Callable
from urllib.parse import quote
from email.message import EmailMessage

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
import smtplib

LOG = logging.getLogger("backup_fg_sqlite_mail_lastentry")


# -----------------------
# Helpers: S3 client, SHA
# -----------------------
def make_s3_client(profile: Optional[str], region: Optional[str]):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("s3", region_name=region)


def sha256_of_file(path: str, block_size: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(block_size), b""):
            h.update(blk)
    return h.hexdigest()


def list_gz_files(directory: str):
    files = []
    try:
        for entry in os.scandir(directory):
            if entry.is_file() and entry.name.endswith(".gz"):
                files.append(entry.path)
    except FileNotFoundError:
        LOG.error("Diretório não encontrado: %s", directory)
        return []
    files.sort(key=lambda p: os.path.getmtime(p))
    return files


# -----------------------
# SQLite helper (no s3_key column)
# -----------------------
def ensure_db(db_path: str):
    d = os.path.dirname(db_path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    # create DB with autocommit (isolation_level=None) to avoid implicit transaction issues
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            s3_url TEXT,
            sha256 TEXT,
            uploaded_at TEXT,
            backup_date TEXT,
            deleted_local INTEGER DEFAULT 0,
            status TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_backups_uploaded_at ON backups(uploaded_at)")
    cur.close()
    return conn


def insert_record(conn: sqlite3.Connection, filename: str, s3_url: Optional[str], sha256: Optional[str], status: str, deleted_local: bool):
    """
    Inserts a record and ensures an immediate commit.
    Note: does not store s3_key.
    """
    uploaded_at = datetime.utcnow().isoformat() + "Z"
    backup_date = date.today().isoformat()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO backups (filename, s3_url, sha256, uploaded_at, backup_date, deleted_local, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (filename, s3_url, sha256, uploaded_at, backup_date, 1 if deleted_local else 0, status),
        )
        conn.commit()
        LOG.debug("Inserted DB record for %s (status=%s)", filename, status)
    finally:
        cur.close()


# -----------------------
# S3 helpers
# -----------------------
def object_exists(s3client, bucket: str, key: str) -> bool:
    try:
        s3client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NotFound"):
            return False
        raise


def make_base_url(s3client, bucket: str, key: str) -> str:
    """
    Builds the object's base URL (without query strings).
    Uses s3client.meta.endpoint_url if available; otherwise uses the AWS default.
    The key is URL-encoded.
    """
    encoded_key = quote(key, safe="/")
    endpoint = getattr(s3client.meta, "endpoint_url", None)
    if endpoint:
        endpoint = endpoint.rstrip("/")
        return f"{endpoint}/{bucket}/{encoded_key}"
    # fallback to virtual-hosted-style
    return f"https://{bucket}.s3.amazonaws.com/{encoded_key}"


# -----------------------
# Email senders (STARTTLS and SMTPS)
# -----------------------
def _normalize_recipients(x: Optional[Iterable[str]]):
    if x is None:
        return []
    if isinstance(x, str):
        return [addr.strip() for addr in x.split(",") if addr.strip()]
    return list(x)


def send_via_starttls(
    smtp_user: str,
    smtp_password: str,
    to_addrs: Iterable[str],
    subject: str,
    body: str,
    from_addr: Optional[str] = None,
    cc_addrs: Optional[Iterable[str]] = None,
    bcc_addrs: Optional[Iterable[str]] = None,
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 587,
    timeout: int = 60,
) -> bool:
    """
    Send via SMTP with STARTTLS (port 587 by default).
    """
    to_list = _normalize_recipients(to_addrs)
    cc_list = _normalize_recipients(cc_addrs)
    bcc_list = _normalize_recipients(bcc_addrs)
    if not to_list and not cc_list and not bcc_list:
        LOG.error("Nenhum destinatário fornecido.")
        return False

    from_addr = from_addr or smtp_user
    recipients = to_list + cc_list + bcc_list

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_list)
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        LOG.debug("Conectando (STARTTLS) %s:%d", smtp_host, smtp_port)
        with smtplib.SMTP(host=smtp_host, port=smtp_port, timeout=timeout) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(smtp_user, smtp_password)
            smtp.send_message(msg, from_addr=from_addr, to_addrs=recipients)
        LOG.info("send_via_starttls: email enviado com sucesso para: %s", recipients)
        return True
    except Exception as e:
        LOG.exception("send_via_starttls: falha ao enviar email: %s", e)
        return False


def send_via_smtps(
    smtp_user: str,
    smtp_password: str,
    to_addrs: Iterable[str],
    subject: str,
    body: str,
    from_addr: Optional[str] = None,
    cc_addrs: Optional[Iterable[str]] = None,
    bcc_addrs: Optional[Iterable[str]] = None,
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 465,
    timeout: int = 60,
) -> bool:
    """
    Send via SMTPS (SMTP over SSL) — port 465 by default.
    """
    to_list = _normalize_recipients(to_addrs)
    cc_list = _normalize_recipients(cc_addrs)
    bcc_list = _normalize_recipients(bcc_addrs)
    if not to_list and not cc_list and not bcc_list:
        LOG.error("Nenhum destinatário fornecido.")
        return False

    from_addr = from_addr or smtp_user
    recipients = to_list + cc_list + bcc_list

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_list)
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        LOG.debug("Conectando (SMTPS) %s:%d", smtp_host, smtp_port)
        with smtplib.SMTP_SSL(host=smtp_host, port=smtp_port, timeout=timeout) as smtp:
            smtp.ehlo()
            smtp.login(smtp_user, smtp_password)
            smtp.send_message(msg, from_addr=from_addr, to_addrs=recipients)
        LOG.info("send_via_smtps: email enviado com sucesso para: %s", recipients)
        return True
    except Exception as e:
        LOG.exception("send_via_smtps: falha ao enviar email: %s", e)
        return False


def run_send(send_func: Callable[..., bool], send_kwargs: Dict, *, dry_run: bool = False) -> bool:
    """
    Calls send_func(**send_kwargs) unless dry_run=True.
    Returns True/False.
    """
    LOG.info("run_send: dry_run=%s func=%s", dry_run, getattr(send_func, "__name__", str(send_func)))
    if dry_run:
        LOG.info("[DRY] Simulação: enviaria com os argumentos abaixo (senha mascarada):")
        for k, v in send_kwargs.items():
            if isinstance(k, str) and ("pass" in k.lower() or "password" in k.lower()):
                LOG.info("  %s: *****", k)
            else:
                LOG.info("  %s: %s", k, v)
        return True

    ok = send_func(**send_kwargs)
    if ok:
        LOG.info("run_send: envio bem sucedido.")
    else:
        LOG.error("run_send: envio falhou.")
    return ok


def test_send(
    method: str,
    *,
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
    smtp_host: Optional[str] = None,
    smtp_port: Optional[int] = None,
    dry_run: bool = False,
) -> bool:
    """
    Sends a test message to the smtp_user using the chosen method.
    method: "starttls" or "smtps"
    """
    smtp_user = smtp_user or os.environ.get("GMAIL_USER")
    smtp_password = smtp_password or os.environ.get("GMAIL_APP_PASSWORD")
    if not smtp_user or not smtp_password:
        LOG.error("Credenciais ausentes: exporte GMAIL_USER e GMAIL_APP_PASSWORD ou passe --smtp-user/--smtp-pass")
        return False

    subject = f"backup_fg test {os.getpid()} {smtp_user}"
    body = "Teste de envio enviado pelo backup_fg.py"

    send_kwargs = {
        "smtp_user": smtp_user,
        "smtp_password": smtp_password,
        "to_addrs": [smtp_user],
        "subject": subject,
        "body": body,
        "from_addr": smtp_user,
    }

    if smtp_host:
        send_kwargs["smtp_host"] = smtp_host
    if smtp_port:
        send_kwargs["smtp_port"] = smtp_port

    if method == "starttls":
        return run_send(send_via_starttls, send_kwargs, dry_run=dry_run)
    elif method == "smtps":
        if "smtp_port" not in send_kwargs:
            send_kwargs["smtp_port"] = 465
        return run_send(send_via_smtps, send_kwargs, dry_run=dry_run)
    else:
        LOG.error("Método desconhecido: %s", method)
        return False


# -----------------------
# Upload logic (base script)
# -----------------------
def upload_one(
    s3client,
    local_path: str,
    bucket: str,
    key: str,
    delete_after: bool = False,
    extra_args: Optional[dict] = None,
    db_conn: Optional[sqlite3.Connection] = None,
) -> bool:
    """
    Upload + verification + sqlite insert (WITHOUT storing s3_key).
    The recorded s3_url is the base URL, built by make_base_url.
    Returns True on success (uploaded or skipped), False on failure.
    """
    extra_args = dict(extra_args or {})
    basename = os.path.basename(local_path)
    LOG.info("Processing %s -> s3://%s/%s", basename, bucket, key)

    # compute local sha
    try:
        local_sha = sha256_of_file(local_path)
    except Exception as e:
        LOG.exception("Failed to compute SHA256 for %s: %s", local_path, e)
        if db_conn:
            insert_record(db_conn, basename, None, None, "failed_sha", False)
        return False

    # If object exists, skip upload but still insert record with base URL
    try:
        if object_exists(s3client, bucket, key):
            LOG.info("Object already exists, skipping upload: s3://%s/%s", bucket, key)
            base_url = make_base_url(s3client, bucket, key)
            if db_conn:
                insert_record(db_conn, basename, base_url, local_sha, "skipped_exists", False)
            return True
    except ClientError as e:
        LOG.error("Cannot check existence for %s: %s", key, e)
        if db_conn:
            insert_record(db_conn, basename, None, local_sha, "failed_head", False)
        return False

    # attach sha metadata and upload
    meta = dict(extra_args.get("Metadata", {}))
    meta["sha256"] = local_sha
    extra_args["Metadata"] = meta

    try:
        s3client.upload_file(local_path, bucket, key, ExtraArgs=extra_args)
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        LOG.exception("Failed upload %s: %s", local_path, e)
        if db_conn:
            insert_record(db_conn, basename, None, local_sha, "failed_upload", False)
        return False

    # validate via head_object metadata
    try:
        head = s3client.head_object(Bucket=bucket, Key=key)
        remote_meta = head.get("Metadata", {}) or {}
        remote_sha = remote_meta.get("sha256")
        if remote_sha is None:
            LOG.error("Uploaded object missing sha256 metadata for %s (s3://%s/%s)", basename, bucket, key)
            if db_conn:
                insert_record(db_conn, basename, None, local_sha, "failed_nometa", False)
            return False
        if remote_sha.lower() != local_sha.lower():
            LOG.error("SHA mismatch for %s: local=%s remote=%s", basename, local_sha, remote_sha)
            if db_conn:
                insert_record(db_conn, basename, None, local_sha, "failed_mismatch", False)
            return False
    except ClientError as e:
        LOG.exception("Failed to head_object for %s after upload: %s", key, e)
        if db_conn:
            insert_record(db_conn, basename, None, local_sha, "failed_head_after", False)
        return False

    # build base URL (no presign)
    base_url = make_base_url(s3client, bucket, key)

    # delete local if requested
    deleted = False
    if delete_after:
        try:
            os.remove(local_path)
            deleted = True
            LOG.info("Deleted local file: %s", local_path)
        except Exception:
            LOG.exception("Could not delete file after verification: %s", local_path)
            deleted = False

    # insert success record (no s3_key)
    if db_conn:
        insert_record(db_conn, basename, base_url, local_sha, "uploaded", deleted)

    LOG.info("Upload and verification complete: %s (sha256=%s)", basename, local_sha)
    return True


def worker_task(
    path,
    bucket,
    prefix,
    s3client,
    delete_after,
    extra_args,
    db_path,
):
    key = os.path.join(prefix, os.path.basename(path)).replace("\\", "/")
    # each worker opens its own sqlite connection for concurrency safety
    db_conn = None
    if db_path:
        try:
            db_conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
        except Exception:
            LOG.exception("Cannot open DB %s", db_path)
            db_conn = None
    try:
        return upload_one(s3client, path, bucket, key, delete_after=delete_after, extra_args=extra_args, db_conn=db_conn)
    finally:
        if db_conn:
            db_conn.close()


# -----------------------
# Utility: fetch last DB entry (most recent id)
# -----------------------
def fetch_last_entry(db_path: str):
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(db_path, timeout=30)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, filename, s3_url, sha256, uploaded_at, backup_date, deleted_local, status "
            "FROM backups ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return None
        keys = ["id", "filename", "s3_url", "sha256", "uploaded_at", "backup_date", "deleted_local", "status"]
        return dict(zip(keys, row))
    except Exception:
        LOG.exception("Erro ao buscar última entrada no DB %s", db_path)
        return None


# -----------------------
# CLI + main
# -----------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Upload .gz logs to S3 and record in sqlite (no s3_key stored, s3_url = base URL).")
    parser.add_argument("--dir", "-d", default=os.environ.get("DIR"), help="Directory with .gz files (env DIR)")
    parser.add_argument("--bucket", "-b", default=os.environ.get("BUCKET"), help="S3 bucket name (env BUCKET)")
    parser.add_argument("--prefix", "-p", default="", help="S3 key prefix (optional, e.g. 'fortigate/')")
    parser.add_argument("--profile", help="AWS profile from ~/.aws/credentials (optional)")
    parser.add_argument("--region", help="AWS region (optional)")
    parser.add_argument("--delete", action="store_true", help="Delete local file after successful upload+verification")
    parser.add_argument("--workers", type=int, default=int(os.environ.get("WORKERS", "4")), help="Number of parallel upload threads")
    parser.add_argument("--acl", default="private", help="ACL for uploaded objects (default: private)")
    parser.add_argument("--prefix-date", action="store_true", help="Add date YYYYMMDD/ to the prefix")
    parser.add_argument("--dry-run", action="store_true", help="List actions but don't perform uploads")
    parser.add_argument("--db-path", default=os.environ.get("DB_PATH", "/var/lib/backup_fg/backup_records.db"), help="Path to sqlite DB file")

    # email/test options (send only; no IMAP checks)
    parser.add_argument("--email-test", action="store_true", help="Run email send test and exit (sends to smtp-user)")
    parser.add_argument("--notify-email", help="Comma-separated email address(es) to receive a summary after run")
    parser.add_argument("--email-method", choices=["starttls", "smtps"], default="starttls", help="Which email send function to use when notifying (default starttls)")
    parser.add_argument("--smtp-user", help="SMTP user (overrides GMAIL_USER env)")
    parser.add_argument("--smtp-pass", help="SMTP password (overrides GMAIL_APP_PASSWORD env)")
    parser.add_argument("--smtp-host", default=None, help="SMTP host (optional override)")
    parser.add_argument("--smtp-port", type=int, default=None, help="SMTP port (optional override)")
    parser.add_argument("--email-dry-run", action="store_true", help="Simulate sending email but do not actually send")

    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # If requested, run email test (send only) and exit
    if args.email_test:
        smtp_user = args.smtp_user or os.environ.get("GMAIL_USER")
        smtp_pass = args.smtp_pass or os.environ.get("GMAIL_APP_PASSWORD")
        if not smtp_user or not smtp_pass:
            LOG.error("Credenciais SMTP ausentes; exporte GMAIL_USER/GMAIL_APP_PASSWORD or use --smtp-user/--smtp-pass")
            sys.exit(3)

        LOG.info("Executando teste de envio via %s (dry=%s)...", args.email_method, args.email_dry_run)
        ok = test_send(args.email_method, smtp_user=smtp_user, smtp_password=smtp_pass, smtp_host=args.smtp_host, smtp_port=args.smtp_port, dry_run=args.email_dry_run)
        sys.exit(0 if ok else 2)

    # --- normal upload flow below ---
    if not args.dir:
        LOG.error("Diretório não informado. Defina a variável de ambiente DIR ou use --dir.")
        sys.exit(1)
    if not args.bucket:
        LOG.error("Bucket não informado. Defina a variável de ambiente BUCKET ou use --bucket.")
        sys.exit(1)

    if args.prefix and not args.prefix.endswith("/"):
        args.prefix += "/"

    if args.prefix_date:
        datestr = time.strftime("%Y%m%d")
        args.prefix = os.path.join(args.prefix, datestr).replace("\\", "/") + "/"

    try:
        s3client = make_s3_client(args.profile, args.region)
    except Exception as e:
        LOG.exception("Error creating S3 client: %s", e)
        sys.exit(1)

    # Prepare DB (main process only) - table created if not exists
    try:
        db_conn = ensure_db(args.db_path)
        db_conn.close()
    except Exception:
        LOG.exception("Could not init DB at %s", args.db_path)
        # continue without DB, but warn
        args.db_path = None

    files = list_gz_files(args.dir)
    if not files:
        LOG.info("No .gz files found in %s", args.dir)
        return

    LOG.info("Found %d .gz files in %s", len(files), args.dir)
    extra_args = {"ACL": args.acl} if args.acl else {}

    if args.dry_run:
        for f in files:
            key = os.path.join(args.prefix, os.path.basename(f)).replace("\\", "/")
            LOG.info("[DRY] Would upload: %s -> s3://%s/%s", f, args.bucket, key)
        return

    successes = 0
    failures = 0
    failed_files = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = []
        for f in files:
            futures.append(
                ex.submit(
                    worker_task,
                    f,
                    args.bucket,
                    args.prefix,
                    s3client,
                    args.delete,
                    extra_args,
                    args.db_path,
                )
            )
        for fut in concurrent.futures.as_completed(futures):
            try:
                ok = fut.result()
            except Exception:
                LOG.exception("Worker crashed")
                ok = False
            if ok:
                successes += 1
            else:
                failures += 1
                failed_files.append("unknown")

    LOG.info("Upload finished. Successes: %d, Failures: %d", successes, failures)

    # If requested, send a summary email that includes the last DB entry (on success) or an error message (on failure)
    if args.notify_email:
        # decide send function from email-method
        if args.email_method == "starttls":
            send_func = send_via_starttls
        else:
            send_func = send_via_smtps

        smtp_user = args.smtp_user or os.environ.get("GMAIL_USER")
        smtp_pass = args.smtp_pass or os.environ.get("GMAIL_APP_PASSWORD")
        if not smtp_user or not smtp_pass:
            LOG.error("Credenciais SMTP ausentes; não será enviado e-mail. Exporte GMAIL_USER and GMAIL_APP_PASSWORD or use --smtp-user/--smtp-pass")
        else:
            to_addrs = [addr.strip() for addr in args.notify_email.split(",") if addr.strip()]

            # fetch last DB entry (if any)
            last = fetch_last_entry(args.db_path)

            if failures == 0:
                # success: send a short message containing last entry
                subj = f"Backup FG: SUCESSO {date.today().isoformat()} - {successes} success"
                if last:
                    body = (
                        f"Backup finalizado com SUCCESS.\n\n"
                        f"Última entrada no DB:\n"
                        f" id: {last.get('id')}\n"
                        f" filename: {last.get('filename')}\n"
                        f" s3_url: {last.get('s3_url') or '-'}\n"
                        f" sha256: {last.get('sha256') or '-'}\n"
                        f" uploaded_at: {last.get('uploaded_at') or '-'}\n"
                        f" backup_date: {last.get('backup_date') or '-'}\n"
                        f" deleted_local: {bool(last.get('deleted_local'))}\n"
                        f" status: {last.get('status') or '-'}\n"
                    )
                else:
                    body = f"Backup finalizado com SUCCESS, mas não há entradas no DB para exibir.\nSucessos: {successes}"
            else:
                # failure: send error message + last entry if exists
                subj = f"Backup FG: ERRO {date.today().isoformat()} - {successes} success / {failures} fail"
                body_lines = [
                    "Ocorreu um erro durante o backup automático.",
                    f"Sucessos: {successes}",
                    f"Falhas: {failures}",
                    "",
                ]
                if last:
                    body_lines.append("Última entrada no DB (pode ser útil para diagnóstico):")
                    body_lines.append(f" id: {last.get('id')}")
                    body_lines.append(f" filename: {last.get('filename')}")
                    body_lines.append(f" s3_url: {last.get('s3_url') or '-'}")
                    body_lines.append(f" sha256: {last.get('sha256') or '-'}")
                    body_lines.append(f" uploaded_at: {last.get('uploaded_at') or '-'}")
                    body_lines.append(f" backup_date: {last.get('backup_date') or '-'}")
                    body_lines.append(f" deleted_local: {bool(last.get('deleted_local'))}")
                    body_lines.append(f" status: {last.get('status') or '-'}")
                else:
                    body_lines.append("Não há entradas no DB para exibir.")
                body = "\n".join(body_lines)

            send_kwargs = {
                "smtp_user": smtp_user,
                "smtp_password": smtp_pass,
                "to_addrs": to_addrs,
                "subject": subj,
                "body": body,
                "from_addr": smtp_user,
            }
            if args.smtp_host:
                send_kwargs["smtp_host"] = args.smtp_host
            if args.smtp_port:
                send_kwargs["smtp_port"] = args.smtp_port

            run_send(send_func, send_kwargs, dry_run=args.email_dry_run)

    if failures:
        sys.exit(2)


if __name__ == "__main__":
    main()
