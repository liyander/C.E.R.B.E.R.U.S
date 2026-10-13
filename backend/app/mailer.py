"""Outbound email: SMTP delivery, an outbox log, branded templates and markdown rendering.

Every message goes through `send`, which records it in the `emails` table so an
admin can see what was sent and what failed. Recipients are always chosen by
the server (users' own addresses); nothing here accepts an arbitrary address
from a model.
"""
import html
import re
import smtplib
import ssl
import threading
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

from .db import db, get_integration, now

ACCENT = "#0f766e"
LEVEL_COLORS = {"info": ACCENT, "warning": "#b45309", "critical": "#b91c1c"}
LEVEL_LABELS = {"info": "Announcement", "warning": "Important notice", "critical": "Critical notice"}
EMAIL_RE = re.compile(r"^[^@\s<>\"',;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+$")
FONT = "font-family:Segoe UI,Helvetica,Arial,sans-serif"
LOGO_CID = "cerberus-logo"
ASSETS = Path(__file__).parent / "assets"
# Images referenced from templates as cid:<name>; attached inside each message that uses them,
# so they show without the reader having to "display images".
IMAGES = {f"banner-{p.stem}": (p.read_bytes(), "jpeg") for p in sorted((ASSETS / "banners").glob("*.jpg"))}
if (ASSETS / "logo.png").exists():
    IMAGES[LOGO_CID] = ((ASSETS / "logo.png").read_bytes(), "png")


class MailError(Exception):
    pass


GMAIL_DOMAINS = ("@gmail.com", "@googlemail.com")


def config(conn) -> dict:
    cfg = get_integration(conn, "email")
    # Settings saved by an earlier version could hold a Gmail address and app password but no
    # server name, which left email silently switched off. Treat those as Gmail.
    address = str(cfg.get("from_email", "")).lower()
    if address.endswith(GMAIL_DOMAINS) and cfg.get("password") and not cfg.get("host"):
        cfg.update(provider="gmail", host="smtp.gmail.com", port=587, security="starttls",
                   username=address, from_email=address, password=cfg["password"].replace(" ", ""))
    return cfg


def is_configured(cfg: dict) -> bool:
    return bool(cfg.get("host") and cfg.get("from_email"))


def _deliver(cfg: dict, recipient: str, subject: str, html_body: str, text_body: str,
             attachments: list[tuple[str, bytes, str, str]] | None = None) -> None:
    msg = EmailMessage()
    msg["From"] = formataddr((cfg.get("from_name") or "CERBERUS", cfg["from_email"]))
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=cfg["from_email"].split("@")[-1])
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    html_part = msg.get_body(("html",))
    for cid in dict.fromkeys(re.findall(r"cid:([A-Za-z0-9-]+)", html_body)):
        if cid in IMAGES:
            data, subtype = IMAGES[cid]
            html_part.add_related(data, maintype="image", subtype=subtype, cid=f"<{cid}>",
                                  filename=f"{cid}.{'jpg' if subtype == 'jpeg' else subtype}", disposition="inline")
    for filename, data, maintype, subtype in attachments or []:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    security = cfg.get("security", "starttls")
    port = int(cfg.get("port") or (465 if security == "ssl" else 587))
    context = ssl.create_default_context()
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(cfg["host"], port, timeout=20, context=context)
        else:
            server = smtplib.SMTP(cfg["host"], port, timeout=20)
        with server:
            if security == "starttls":
                server.starttls(context=context)
            if cfg.get("username"):
                server.login(cfg["username"], cfg.get("password", ""))
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        if cfg.get("provider") == "gmail":
            raise MailError("Gmail rejected the sign-in. Use a 16-letter app password (not your normal password); "
                            "2-Step Verification must be turned on for the Google account.") from exc
        raise MailError("The mail server rejected the username or password.") from exc
    except (smtplib.SMTPException, OSError, ValueError) as exc:
        raise MailError(str(exc)[:300] or exc.__class__.__name__) from exc


def send(conn, kind: str, recipients: list[str], message: tuple[str, str, str], wait: bool = False,
         attachments: list[tuple[str, bytes, str, str]] | None = None) -> int:
    """Queue (or, with wait=True, deliver now) one email per recipient. Returns how many were queued."""
    cfg = config(conn)
    if not is_configured(cfg):
        raise MailError("Email is not configured. An admin can set it up under Integrations.")
    subject, html_body, text_body = message
    app_url = str(cfg.get("app_url", ""))
    html_body = html_body.replace(APP_LINK, f' &nbsp;&middot;&nbsp; <a href="{html.escape(app_url, quote=True)}" '
                                            f'style="color:{ACCENT}">Open the console</a>' if app_url else "")
    subject = " ".join(subject.split())[:200]
    queued = []
    for recipient in dict.fromkeys(r.strip().lower() for r in recipients if r and EMAIL_RE.match(r.strip())):
        cur = conn.execute("INSERT INTO emails (kind, recipient, subject, created_at) VALUES (?, ?, ?, ?)",
                           (kind, recipient, subject, now()))
        queued.append((cur.lastrowid, recipient))
    errors = []

    def work():
        with db() as own:
            for email_id, recipient in queued:
                try:
                    _deliver(cfg, recipient, subject, html_body, text_body, attachments)
                    own.execute("UPDATE emails SET status = 'sent', sent_at = ? WHERE id = ?", (now(), email_id))
                except MailError as exc:
                    errors.append(str(exc))
                    own.execute("UPDATE emails SET status = 'failed', error = ? WHERE id = ?", (str(exc), email_id))

    if wait:
        work()
        if errors:
            raise MailError(errors[0])
    elif queued:
        threading.Thread(target=work, daemon=True).start()
    return len(queued)


# ---------- markdown -> email-safe HTML (escape first) ----------

def _inline(text: str) -> str:
    parts = text.split("`")
    if len(parts) % 2 == 0:  # unmatched backtick stays literal
        parts[-2:] = [parts[-2] + "`" + parts[-1]]
    out = []
    for i, seg in enumerate(parts):
        seg = html.escape(seg)
        if i % 2:
            out.append(f'<code style="background:#f1f3f4;border-radius:4px;padding:1px 5px;font-family:Consolas,monospace;font-size:13px">{seg}</code>')
            continue
        seg = re.sub(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", rf'<a href="\2" style="color:{ACCENT}">\1</a>', seg)
        seg = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", seg)
        seg = re.sub(r"(^|[\s(])\*([^*\s][^*]*)\*(?=[\s).,;:!?]|$)", r"\1<em>\2</em>", seg)
        out.append(seg)
    return "".join(out)


def _cells(line: str) -> list[str]:
    cells, cur, code = [], "", False
    for ch in line.strip():
        if ch == "`":
            code = not code
        if ch == "|" and not code:
            cells.append(cur)
            cur = ""
        else:
            cur += ch
    cells.append(cur)
    if cells and not cells[0].strip():
        cells.pop(0)
    if cells and not cells[-1].strip():
        cells.pop()
    return [c.strip() for c in cells]


_LIST = re.compile(r"^(\s*)([-*+•]|\d+[.)])\s+(.*)")
_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def md_to_html(text: str) -> str:
    lines = str(text or "").replace("\r", "").split("\n")
    out, para, list_tag = [], [], ""
    td = "padding:7px 10px;border:1px solid #e2e5e7;font-size:14px;text-align:left"

    def flush():
        nonlocal para, list_tag
        if para:
            out.append(f'<p style="margin:10px 0">{"<br>".join(_inline(p) for p in para)}</p>')
            para = []
        if list_tag:
            out.append(f"</{list_tag}>")
            list_tag = ""

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            flush()
            block = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            out.append('<pre style="background:#f1f3f4;border-radius:8px;padding:12px;font-family:Consolas,monospace;'
                       f'font-size:13px;white-space:pre-wrap">{html.escape(chr(10).join(block))}</pre>')
        elif "|" in line and i + 1 < len(lines) and "-" in lines[i + 1] and _SEP.match(lines[i + 1]):
            flush()
            head = _cells(line)
            rows = []
            i += 2
            while i < len(lines) and lines[i].strip() and "|" in lines[i]:
                rows.append(_cells(lines[i]))
                i += 1
            i -= 1
            out.append('<table cellspacing="0" cellpadding="0" style="border-collapse:collapse;margin:12px 0;width:100%">'
                       "<tr>" + "".join(f'<th style="{td};background:#f6f7f8">{_inline(c)}</th>' for c in head) + "</tr>"
                       + "".join("<tr>" + "".join(f'<td style="{td}">{_inline(r[k] if k < len(r) else "")}</td>'
                                                  for k in range(len(head))) + "</tr>" for r in rows) + "</table>")
        elif not line.strip():
            flush()
        elif m := re.match(r"^\s*(#{1,6})\s+(.*?)\s*#*\s*$", line):
            flush()
            size = "18px" if len(m[1]) <= 2 else "15px"
            out.append(f'<h3 style="margin:20px 0 6px;font-size:{size};color:#111">{_inline(m[2])}</h3>')
        elif re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line):
            flush()
            out.append('<hr style="border:0;border-top:1px solid #e2e5e7;margin:16px 0">')
        elif line.lstrip().startswith(">"):
            flush()
            out.append('<blockquote style="margin:10px 0;padding:2px 14px;border-left:3px solid #cfd4d8;color:#555">'
                       f'{_inline(line.lstrip()[1:].strip())}</blockquote>')
        elif m := _LIST.match(line):
            tag = "ol" if m[2][0].isdigit() else "ul"
            if para or list_tag != tag:
                flush()
                out.append(f'<{tag} style="margin:8px 0;padding-left:24px">')
                list_tag = tag
            indent = len(m[1].replace("\t", "    ")) // 2 * 16
            # Keep the author's numbering even when a nested bullet list interrupted the numbered one.
            number = f' value="{int(m[2][:-1])}"' if tag == "ol" else ""
            out.append(f'<li{number} style="margin:3px 0 3px {indent}px">{_inline(m[3])}</li>')
        else:
            if list_tag:
                flush()
            para.append(line)
        i += 1
    flush()
    return "".join(out)


# ---------- templates: each returns (subject, html, text) ----------
# Editorial layout for mail clients: a picture banner, a large centred headline with one
# highlighted phrase, a coloured key line, a pill button and plenty of white space.
# Tables + inline styles only; images travel inside the message.

INK = "#161616"
BODY = "#2b2b2b"
QUIET = "#77756f"
RULE = "#e4e2db"
PAPER = "#fdfdfb"
MARK = "#ffe08a"       # highlighter behind the key phrase of a headline
SANS = "font-family:'Helvetica Neue',Helvetica,Arial,sans-serif"
LEVEL_BANNERS = {"info": "announcement", "warning": "important", "critical": "critical"}
APP_LINK = "__CERBERUS_APP_LINK__"  # replaced in send() with the configured address of the app


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")


def _headline(text: str) -> str:
    """'Reset your [[password]]' -> escaped text with the bracketed phrase highlighted."""
    out = []
    for i, part in enumerate(re.split(r"\[\[(.+?)\]\]", text)):
        part = html.escape(part)
        out.append(f'<span style="background:{MARK};padding:0 7px;border-radius:2px">{part}</span>' if i % 2 else part)
    return "".join(out)


def _plain(text: str) -> str:
    return re.sub(r"\[\[(.+?)\]\]", r"\1", text)


def _divider(width: str = "56%") -> str:
    return (f'<table width="{width}" align="center" cellspacing="0" cellpadding="0" style="margin:38px auto"><tr>'
            f'<td style="border-top:1px solid {RULE};font-size:0;line-height:0">&nbsp;</td></tr></table>')


def layout(*, banner: str, headline: str, lead: str = "", key_line: str = "", key_sub: str = "", accent: str = ACCENT,
           button: tuple[str, str] | None = None, details_title: str = "", details: list[tuple[str, str]] | None = None,
           body_html: str = "", note: str = "", preheader: str = "") -> str:
    centre = f"text-align:center;{SANS}"
    parts = [f'<h1 style="margin:0;font-size:33px;line-height:1.22;font-weight:700;color:{INK};{centre}">{_headline(headline)}</h1>']
    if lead:
        parts.append(f'<p style="margin:20px auto 0;max-width:470px;font-size:18px;line-height:1.55;color:{BODY};{centre}">{html.escape(lead)}</p>')
    if key_line:
        parts.append(f'<p style="margin:34px 0 0;font-size:24px;line-height:1.3;font-weight:700;color:{accent};{centre}">{html.escape(key_line)}</p>')
    if key_sub:
        parts.append(f'<p style="margin:6px 0 0;font-size:15px;color:{accent};{centre}">{html.escape(key_sub)}</p>')
    if button:
        text, url = button
        safe = html.escape(url, quote=True)
        parts.append(
            f'<table align="center" cellspacing="0" cellpadding="0" style="margin:26px auto 0"><tr><td style="background:{accent};border-radius:999px">'
            f'<a href="{safe}" style="display:inline-block;padding:15px 34px;color:#ffffff;text-decoration:none;font-weight:700;'
            f'font-size:17px;{SANS}">{html.escape(text)}</a></td></tr></table>'
            f'<p style="margin:14px auto 0;max-width:440px;font-size:12px;line-height:1.5;color:{QUIET};word-break:break-all;{centre}">'
            f'Or paste this link into your browser:<br>{html.escape(url)}</p>')
    rows = [(k, v) for k, v in (details or []) if v]
    if rows or body_html:
        parts.append(_divider())
    if details_title:
        parts.append(f'<p style="margin:0 0 6px;font-size:18px;font-weight:700;color:{INK};{centre}">{html.escape(details_title)}</p>')
    for label, value in rows:
        parts.append(f'<p style="margin:0;font-size:17px;line-height:1.7;color:{BODY};{centre}">'
                     f'<span style="color:{QUIET}">{html.escape(label)}</span>&nbsp; <strong style="color:{INK}">{html.escape(value)}</strong></p>')
    if body_html:
        gap = "26px" if rows else "0"
        parts.append(f'<div style="margin:{gap} auto 0;max-width:500px;text-align:left;font-size:16px;line-height:1.6;color:{BODY};{SANS}">{body_html}</div>')
    if note:
        parts.append(f'<p style="margin:34px auto 0;max-width:450px;font-size:13.5px;line-height:1.55;color:{QUIET};{centre}">{html.escape(note)}</p>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f3f2ee">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">{html.escape(preheader or _plain(headline))}</div>
<table width="100%" cellspacing="0" cellpadding="0" style="background:#f3f2ee"><tr><td align="center" style="padding:0 0 36px">
<table width="600" cellspacing="0" cellpadding="0" style="max-width:600px;width:100%;background:{PAPER}">
<tr><td style="font-size:0;line-height:0"><img src="cid:banner-{banner}" width="600" alt="CERBERUS" style="display:block;width:100%;max-width:600px;height:auto;border:0"></td></tr>
<tr><td style="padding:46px 36px 44px">{"".join(parts)}</td></tr>
<tr><td style="padding:0 36px 34px;text-align:center;{SANS}">
  <table width="100%" cellspacing="0" cellpadding="0"><tr><td style="border-top:1px solid {RULE};font-size:0;line-height:0;padding-bottom:26px">&nbsp;</td></tr></table>
  <img src="cid:{LOGO_CID}" width="34" height="34" alt="" style="display:inline-block;border:0">
  <p style="margin:10px 0 0;font-size:13px;line-height:1.6;color:{QUIET}"><strong style="color:{INK};letter-spacing:2px">CERBERUS</strong><br>
  AI-assisted security operations{APP_LINK}<br>This message was sent automatically. Replies are not read.</p></td></tr>
</table></td></tr></table></body></html>"""


def verify_email(username: str, link: str, needs_password: bool, invited_by: str = "", role: str = "") -> tuple[str, str, str]:
    as_role = f" as {'an' if role == 'analyst' or role == 'admin' else 'a'} {role}" if role else ""
    intro = (f"{invited_by} has added you to the CERBERUS security operations console{as_role}."
             if invited_by else "Confirm that this email address is yours to activate your CERBERUS account.")
    action = ("Confirm your address and choose a password to get started." if needs_password
              else "Confirm your address to get started.")
    button = "Verify and set password" if needs_password else "Verify my account"
    text = (f"{intro}\n{action}\n\n{link}\n\nAccount: {username}\nThe link works once and expires in 72 hours.\n"
            "If you were not expecting this, you can ignore the email.")
    return ("Verify your CERBERUS account",
            layout(banner="account", headline="You're invited to [[CERBERUS]]" if invited_by else "Confirm your [[email address]]",
                   lead=f"{intro} {action}", key_line="Your link expires in 72 hours", key_sub="It can be used once",
                   button=(button, link), details_title="Your account:",
                   details=[("Username", username), ("Role", role.capitalize()), ("Invited by", invited_by)],
                   note="Not expecting this? Ignore the email and nothing will happen.", preheader=action), text)


def reset_email(username: str, link: str) -> tuple[str, str, str]:
    line = "Someone asked to reset the password for your CERBERUS account. Choose a new one with the button below."
    text = (f"{line}\n\n{link}\n\nAccount: {username}\nThe link works once and expires in 1 hour.\n"
            "If you did not ask for this, ignore the email; your password is unchanged.")
    return ("Reset your CERBERUS password",
            layout(banner="reset", headline="Reset your [[password]]", lead=line, key_line="Your link expires in 1 hour",
                   key_sub=f"Requested {stamp()}", button=("Choose a new password", link),
                   details_title="This request is for:", details=[("Account", username)],
                   note="Did not ask for this? Ignore the email. Your current password keeps working until a new one is chosen.",
                   preheader="Use this link within one hour to choose a new password."), text)


def password_changed_email(username: str) -> tuple[str, str, str]:
    line = "The password for your CERBERUS account was changed, and every other device was signed out."
    warn = "If this was not you, tell an admin now so the account can be locked."
    return ("Your CERBERUS password was changed",
            layout(banner="security", headline="Your password was [[changed]]", lead=line, accent="#b91c1c",
                   key_line="Was this you?", key_sub=warn, details_title="What changed:",
                   details=[("Account", username), ("When", stamp())], preheader=line),
            f"{line}\n\nAccount: {username}\nChanged: {stamp()}\n\n{warn}")


def address_added_email(username: str, address: str = "") -> tuple[str, str, str]:
    line = "This address is now linked to your CERBERUS admin account, and email delivery to it works."
    warn = "Did not add this address? Sign in and change it under Users."
    return ("Your CERBERUS email address is confirmed",
            layout(banner="account", headline="Email address [[confirmed]]", lead=line,
                   details_title="You will now receive:",
                   details=[("Analyst reports", "as PDF attachments"), ("Announcements", "from your team"),
                            ("Password resets", "for your own account")],
                   note=f"Linked to the account {username} on {stamp()}. {warn}", preheader="Email delivery to this address works."),
            f"{line}\n\nAccount: {username}\n\n{warn}")


def test_email(sender: str) -> tuple[str, str, str]:
    line = "CERBERUS can now send invitations, password resets, analyst reports and announcements."
    return ("CERBERUS test email",
            layout(banner="test", headline="Email delivery [[works]]", lead=line, details_title="This test:",
                   details=[("Sent by", sender), ("Sent", stamp())], preheader="Email delivery from CERBERUS is working."),
            f"Email delivery from CERBERUS is working.\n{line}\n\nSent by {sender} at {stamp()}.")


def _excerpt(markdown: str, limit: int = 700) -> tuple[str, bool]:
    """Leading blocks of a report, cut on a blank line so tables and lists stay whole."""
    blocks, size = [], 0
    for block in re.split(r"\n\s*\n", markdown.strip()):
        if blocks and size + len(block) > limit:
            return "\n\n".join(blocks), True
        blocks.append(block)
        size += len(block)
    return "\n\n".join(blocks), False


def report_email(requested_by: str, subject: str, question: str, report_md: str, app_url: str,
                 attachment_name: str = "") -> tuple[str, str, str]:
    preview, cut = _excerpt(report_md)
    body = (f'<p style="margin:0 0 10px;font-size:13px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:{QUIET}">'
            f'{"Preview" if cut else "Report"}</p>' + md_to_html(preview)
            + (f'<p style="margin:16px 0 0;color:{QUIET};font-size:14px">The report continues in the attached PDF.</p>' if cut else ""))
    text = (f"Report requested by {requested_by} at {stamp()}\n" + (f"Question: {question}\n" if question else "")
            + (f"The full report is attached: {attachment_name}\n" if attachment_name else "") + f"\n{report_md}")
    return (f"[CERBERUS report] {subject}",
            layout(banner="report", headline=subject, lead=f"Requested by {requested_by} on {stamp()}.",
                   key_line="Full report attached as a PDF" if attachment_name else "", key_sub=attachment_name,
                   button=("Open CERBERUS", app_url) if app_url else None,
                   details_title="The question asked:" if question else "",
                   details=[("", " ".join(question.split())[:300])] if question else None, body_html=body,
                   note="Written by the CERBERUS AI analyst from evidence it retrieved. Check the findings before acting on them.",
                   preheader=f"Report requested by {requested_by}."), text)


def report_message(requested_by: str, subject: str, question: str, report_md: str, app_url: str):
    """The report email plus its PDF attachment. Returns (message, attachments)."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", subject).strip("-")[:40] or "report"
    name = f"CERBERUS-report-{slug}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    try:
        from . import report_pdf
        attachment = (f"{name}.pdf", report_pdf.build(subject, requested_by, stamp(), question, report_md), "application", "pdf")
    except Exception:  # a missing PDF library or an odd character must not stop the report going out
        attachment = (f"{name}.md", report_md.encode("utf-8"), "text", "markdown")
    return report_email(requested_by, subject, question, report_md, app_url, attachment[0]), [attachment]


def watch_email(findings: list[dict], writeup_md: str, worst: int, app_url: str) -> tuple[str, str, str]:
    count = len(findings)
    first = findings[0]["title"]
    listing = "\n".join(f"- **{f['title']}**: {f['detail']}" for f in findings)
    body = md_to_html(listing)
    if writeup_md:
        body += (f'<p style="margin:26px 0 8px;font-size:13px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:{QUIET}">'
                 "AI analyst</p>" + md_to_html(writeup_md))
    critical = worst >= 9
    return (f"[CERBERUS watch] {first}" + (f" and {count - 1} more" if count > 1 else ""),
            layout(banner="watch-critical" if critical else "watch", accent="#b91c1c" if critical else "#b45309",
                   headline=first if count == 1 else f"[[{count} conditions]] need attention",
                   lead="The scheduled AI analyst found this during its latest check of your servers and logs.",
                   button=("Open AI watch", f"{app_url}/#/watch") if app_url else None, body_html=body,
                   note="You receive this as a CERBERUS admin. Limits, quiet periods and these emails can be changed on the AI watch page.",
                   preheader=first),
            f"CERBERUS watch: {count} new condition(s)\n\n" + "\n".join(f"- {f['title']}: {f['detail']}" for f in findings)
            + (f"\n\nAI analyst:\n{writeup_md}" if writeup_md else ""))


def digest_email(text_md: str, firing: int, app_url: str) -> tuple[str, str, str]:
    day = datetime.now(timezone.utc).strftime("%d %b %Y")
    status = f"{firing} condition{'' if firing == 1 else 's'} need{'s' if firing == 1 else ''} attention" if firing else "Nothing needs attention right now"
    return (f"[CERBERUS] Daily digest, {day}",
            layout(banner="digest", headline="Your daily [[security digest]]", lead=f"The last 24 hours, as of {stamp()}.",
                   key_line=status, accent="#b45309" if firing else ACCENT, body_html=md_to_html(text_md),
                   button=("Open CERBERUS", app_url) if app_url else None,
                   note="Sent once a day by the AI watch. The time, or the digest itself, can be changed on the AI watch page.",
                   preheader=status),
            f"CERBERUS daily digest, {day}\n{status}\n\n{text_md}")


def announcement_email(title: str, message_md: str, level: str, author: str, audience: str = "all") -> tuple[str, str, str]:
    label = LEVEL_LABELS.get(level, LEVEL_LABELS["info"])
    prefix = "" if level == "info" else f"[{label}] "
    to = {"all": "everyone on the team", "admins": "the admins", "analysts": "the analysts"}.get(audience, "the team")
    return (f"{prefix}{title}",
            layout(banner=LEVEL_BANNERS.get(level, "announcement"), headline=title, accent=LEVEL_COLORS.get(level, ACCENT),
                   body_html=md_to_html(message_md),
                   note=f"Sent by {author} to {to} on {stamp()}.", preheader=" ".join(message_md.split())[:120]),
            f"{label}: {title}\n\n{message_md}\n\nSent by {author} to {to}, {stamp()}.")
