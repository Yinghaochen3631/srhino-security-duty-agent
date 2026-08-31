#!/usr/bin/env python3
"""Send a Srhino HTML duty report, or report that SMTP is not configured."""
from __future__ import annotations

import argparse
import datetime as dt
import email.message
import mimetypes
import os
import pathlib
import smtplib
import ssl


def main() -> int:
    parser = argparse.ArgumentParser(description="发送 Srhino HTML 值守日报")
    parser.add_argument("--html", required=True, type=pathlib.Path)
    parser.add_argument("--markdown", required=True, type=pathlib.Path)
    parser.add_argument("--date", required=True)
    parser.add_argument("--recipient", default=os.getenv("SRHINO_DUTY_RECIPIENT", "1622363185@qq.com"))
    args = parser.parse_args()

    host = os.getenv("SRHINO_SMTP_HOST", "").strip()
    user = os.getenv("SRHINO_SMTP_USER", "").strip()
    password = os.getenv("SRHINO_SMTP_PASSWORD", "")
    sender = os.getenv("SRHINO_SMTP_FROM", user).strip()
    port = int(os.getenv("SRHINO_SMTP_PORT", "465"))
    if not host or not user or not password or not sender:
        print('{"status":"pending_configuration","recipient":"%s","message":"SMTP 发件配置未完成，HTML 已生成但未发送"}' % args.recipient)
        return 0

    html_content = args.html.read_text(encoding="utf-8")
    markdown_content = args.markdown.read_text(encoding="utf-8")
    message = email.message.EmailMessage()
    message["Subject"] = f"Srhino安全告警值守日报｜{args.date}"
    message["From"] = sender
    message["To"] = args.recipient
    message.set_content(markdown_content)
    message.add_alternative(html_content, subtype="html")
    data = args.html.read_bytes()
    maintype, subtype = mimetypes.guess_type(args.html.name)[0].split("/", 1) if mimetypes.guess_type(args.html.name)[0] else ("text", "html")
    message.add_attachment(data, maintype=maintype, subtype=subtype, filename=args.html.name)

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=30) as smtp:
                smtp.login(user, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=30) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(user, password)
                smtp.send_message(message)
    except Exception as exc:  # Keep the daily report available even when mail fails.
        print('{"status":"failed","recipient":"%s","error":"%s"}' % (args.recipient, str(exc).replace('"', "'")))
        return 0
    print('{"status":"sent","recipient":"%s","sent_at":"%s","attachment":"%s"}' % (args.recipient, dt.datetime.now(dt.timezone.utc).isoformat(), args.html.name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
