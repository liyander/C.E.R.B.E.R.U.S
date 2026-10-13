"""Accounts and team communication: sign-in, verification, password reset,
user management, email settings, announcements and in-app notifications."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import auth, mailer
from .db import audit, db, now, set_integration

router = APIRouter(prefix="/api/v1")
User = Depends(auth.current_user)
Admin = Depends(auth.require_admin)

USERNAME = r"^[A-Za-z0-9_.-]+$"
EMAIL = r"^[^@\s<>\"',;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+$"
OPTIONAL_EMAIL = r"^([^@\s<>\"',;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+)?$"
AUDIENCES = {"all": ("admin", "analyst"), "admins": ("admin",), "analysts": ("analyst",)}
BAD_LINK = "This link is invalid or has expired. Ask for a new one."


class SetupBody(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=USERNAME)
    password: str = Field(min_length=10, max_length=200)
    email: str = Field(default="", max_length=200, pattern=OPTIONAL_EMAIL)


class LoginBody(BaseModel):
    username: str = Field(max_length=200)
    password: str = Field(max_length=200)


class ForgotBody(BaseModel):
    identifier: str = Field(min_length=1, max_length=200)


class TokenBody(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(default="", max_length=200)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=USERNAME)
    email: str = Field(max_length=200, pattern=EMAIL)
    role: str = Field(pattern=r"^(admin|analyst)$")
    password: str = Field(default="", max_length=200)


class UserUpdate(BaseModel):
    email: str | None = Field(default=None, max_length=200, pattern=EMAIL)
    role: str | None = Field(default=None, pattern=r"^(admin|analyst)$")
    disabled: bool | None = None
    email_verified: bool | None = None
    password: str | None = Field(default=None, min_length=10, max_length=200)


class PasswordChange(BaseModel):
    current: str = Field(max_length=200)
    new: str = Field(min_length=10, max_length=200)


class EmailSettings(BaseModel):
    provider: str = Field(default="gmail", pattern=r"^(gmail|custom)$")
    host: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9.-]*$")
    port: int = Field(default=587, ge=1, le=65535)
    security: str = Field(default="starttls", pattern=r"^(starttls|ssl|none)$")
    username: str = Field(default="", max_length=200)
    password: str = Field(default="", max_length=500)
    from_email: str = Field(default="", max_length=200, pattern=OPTIONAL_EMAIL)
    from_name: str = Field(default="CERBERUS", max_length=80, pattern=r"^[^\r\n<>\"]*$")
    app_url: str = Field(default="", max_length=300, pattern=r"^(https?://[^\s]+)?$")


class AnnouncementBody(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    message: str = Field(min_length=1, max_length=5000)
    level: str = Field(default="info", pattern=r"^(info|warning|critical)$")
    audience: str = Field(default="all", pattern=r"^(all|admins|analysts)$")
    in_app: bool = True
    email: bool = False


# ---------- helpers ----------

def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def set_cookie(request: Request, response: Response, token: str) -> None:
    response.set_cookie(auth.COOKIE, token, max_age=auth.SESSION_HOURS * 3600, httponly=True,
                        samesite="strict", secure=request.url.scheme == "https", path="/")


def app_url(conn, request: Request) -> str:
    """Links in emails use the admin-configured address; the request host is only a fallback."""
    return (mailer.config(conn).get("app_url") or str(request.base_url)).rstrip("/")


def admin_emails(conn) -> list[str]:
    return [r["email"] for r in conn.execute(
        "SELECT email FROM users WHERE role = 'admin' AND disabled = 0 AND email_verified = 1 AND email != ''")]


def unread_count(conn, user: dict) -> int:
    audiences = ("all", "admins" if user["role"] == "admin" else "analysts")
    return conn.execute(
        "SELECT COUNT(*) FROM notifications n WHERE n.in_app = 1 AND n.audience IN (?, ?) AND NOT EXISTS "
        "(SELECT 1 FROM notification_reads r WHERE r.notification_id = n.id AND r.user_id = ?)",
        (*audiences, user["id"])).fetchone()[0]


def _send_verification(conn, request: Request, row, invited_by: str = "") -> None:
    token = auth.issue_token(conn, row["id"], "verify")
    link = f"{app_url(conn, request)}/#/verify?token={token}"
    mailer.send(conn, "verify", [row["email"]],
                mailer.verify_email(row["username"], link, needs_password=not row["pw_hash"], invited_by=invited_by,
                                    role=row["role"]))


def _user_or_404(conn, user_id: int):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(404, "User not found")
    return row


def _other_active_admins(conn, user_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?",
                        (user_id,)).fetchone()[0]


def _check_unique(conn, username: str | None, email: str | None, except_id: int = 0) -> None:
    if username and conn.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE AND id != ?",
                                 (username, except_id)).fetchone():
        raise HTTPException(409, "That username is already taken")
    if email and conn.execute("SELECT 1 FROM users WHERE email = ? AND id != ?", (email.lower(), except_id)).fetchone():
        raise HTTPException(409, "Another account already uses that email address")


# ---------- sign-in, verification, password reset ----------

@router.get("/auth/state")
def auth_state(request: Request):
    with db() as conn:
        setup_required = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        user = auth.lookup_user(conn, request.cookies.get(auth.COOKIE))
        return {"setup_required": setup_required, "user": dict(user) if user else None,
                "email_configured": mailer.is_configured(mailer.config(conn))}


@router.post("/auth/setup")
def auth_setup(body: SetupBody, request: Request, response: Response):
    with db() as conn:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise HTTPException(409, "An admin account already exists")
        # The person performing first-run setup is trusted as the first, verified admin.
        user_id = auth.create_user(conn, body.username, body.password, email=body.email, role="admin", verified=True)
        audit(conn, body.username, "auth.setup", {"client": client_ip(request)})
        set_cookie(request, response, auth.create_session(conn, user_id))
    return {"ok": True}


@router.post("/auth/login")
def auth_login(body: LoginBody, request: Request, response: Response):
    with db() as conn:
        user = auth.verify_login(conn, body.username.strip(), body.password, client_ip(request))
        if not user:
            audit(conn, body.username[:64], "auth.login_failed", {"client": client_ip(request)})
            raise HTTPException(401, "Wrong username or password")
        # Account state is only revealed after the password was correct.
        if user["disabled"]:
            raise HTTPException(403, "This account is disabled. Contact an admin.")
        if not user["email_verified"]:
            raise HTTPException(403, "Verify your email address first: use the link we emailed you, "
                                     "or ask an admin to send a new one.")
        audit(conn, user["username"], "auth.login", {"client": client_ip(request)})
        set_cookie(request, response, auth.create_session(conn, user["id"]))
    return {"ok": True}


@router.post("/auth/logout")
def auth_logout(request: Request, response: Response):
    with db() as conn:
        auth.delete_session(conn, request.cookies.get(auth.COOKIE, ""))
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@router.post("/auth/forgot")
def auth_forgot(body: ForgotBody, request: Request):
    auth.throttle(f"forgot:{client_ip(request)}", limit=5, seconds=900)
    ident = body.identifier.strip()
    with db() as conn:
        if not mailer.is_configured(mailer.config(conn)):
            raise HTTPException(409, "Email is not set up on this server. Ask an admin to reset your password.")
        row = conn.execute("SELECT * FROM users WHERE disabled = 0 AND email != '' AND "
                           "(username = ? COLLATE NOCASE OR email = ?)", (ident, ident.lower())).fetchone()
        if row:
            token = auth.issue_token(conn, row["id"], "reset")
            link = f"{app_url(conn, request)}/#/reset?token={token}"
            mailer.send(conn, "reset", [row["email"]], mailer.reset_email(row["username"], link))
        audit(conn, ident[:64], "auth.forgot", {"client": client_ip(request), "matched": bool(row)})
    # Same answer whether or not the account exists.
    return {"ok": True}


@router.get("/auth/token")
def auth_token_info(token: str, kind: str, request: Request):
    auth.throttle(f"token:{client_ip(request)}", limit=30, seconds=300)
    if kind not in auth.TOKEN_HOURS:
        raise HTTPException(404, BAD_LINK)
    with db() as conn:
        row = auth.token_user(conn, token, kind)
    if not row:
        raise HTTPException(404, BAD_LINK)
    return {"username": row["username"], "needs_password": kind == "reset" or not row["pw_hash"]}


@router.post("/auth/verify")
def auth_verify(body: TokenBody, request: Request):
    auth.throttle(f"token:{client_ip(request)}", limit=30, seconds=300)
    with db() as conn:
        row = auth.token_user(conn, body.token, "verify")
        if not row:
            raise HTTPException(404, BAD_LINK)
        if not row["pw_hash"]:
            if len(body.password) < 10:
                raise HTTPException(422, "Choose a password of at least 10 characters")
            auth.set_password(conn, row["id"], body.password)
        conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["id"],))
        auth.consume_token(conn, body.token)
        audit(conn, row["username"], "auth.verified", {"client": client_ip(request)})
    return {"ok": True, "username": row["username"]}


@router.post("/auth/reset")
def auth_reset(body: TokenBody, request: Request):
    auth.throttle(f"token:{client_ip(request)}", limit=30, seconds=300)
    if len(body.password) < 10:
        raise HTTPException(422, "Choose a password of at least 10 characters")
    with db() as conn:
        row = auth.token_user(conn, body.token, "reset")
        if not row:
            raise HTTPException(404, BAD_LINK)
        auth.set_password(conn, row["id"], body.password)
        # Using a link sent to the address also proves the address is theirs.
        conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["id"],))
        auth.consume_token(conn, body.token)
        audit(conn, row["username"], "auth.password_reset", {"client": client_ip(request)})
        try:
            mailer.send(conn, "password_changed", [row["email"]], mailer.password_changed_email(row["username"]))
        except mailer.MailError:
            pass
    return {"ok": True, "username": row["username"]}


@router.put("/account/password")
def account_password(body: PasswordChange, request: Request, response: Response, user=User):
    auth.throttle(f"pw:{user['id']}", limit=8, seconds=300)
    with db() as conn:
        row = _user_or_404(conn, user["id"])
        if not auth.check_password(row, body.current):
            raise HTTPException(403, "Your current password is not correct")
        auth.set_password(conn, user["id"], body.new)
        set_cookie(request, response, auth.create_session(conn, user["id"]))
        audit(conn, user["username"], "account.password_changed")
        try:
            mailer.send(conn, "password_changed", [row["email"]], mailer.password_changed_email(row["username"]))
        except mailer.MailError:
            pass
    return {"ok": True}


# ---------- user management (admin) ----------

def _public_user(row) -> dict:
    return {"id": row["id"], "username": row["username"], "email": row["email"], "role": row["role"],
            "email_verified": bool(row["email_verified"]), "disabled": bool(row["disabled"]),
            "has_password": bool(row["pw_hash"]), "created_at": row["created_at"], "last_login": row["last_login"]}


@router.get("/users")
def users_list(admin=Admin):
    with db() as conn:
        return {"users": [_public_user(r) for r in conn.execute("SELECT * FROM users ORDER BY role, username")],
                "email_configured": mailer.is_configured(mailer.config(conn))}


@router.post("/users")
def users_create(body: UserCreate, request: Request, admin=Admin):
    if body.password and len(body.password) < 10:
        raise HTTPException(422, "The initial password must be at least 10 characters")
    with db() as conn:
        _check_unique(conn, body.username, body.email)
        configured = mailer.is_configured(mailer.config(conn))
        if not body.password and not configured:
            raise HTTPException(409, "Email is not configured yet, so set an initial password for this user.")
        # Without email there is nothing to verify against; the admin vouches for the account.
        user_id = auth.create_user(conn, body.username, body.password, email=body.email, role=body.role,
                                   verified=not configured)
        if configured:
            _send_verification(conn, request, _user_or_404(conn, user_id), invited_by=admin["username"])
        audit(conn, admin["username"], "user.created", {"username": body.username, "role": body.role})
    return {"id": user_id, "invited": configured}


@router.put("/users/{user_id}")
def users_update(user_id: int, body: UserUpdate, request: Request, admin=Admin):
    with db() as conn:
        row = _user_or_404(conn, user_id)
        loses_admin = row["role"] == "admin" and not row["disabled"] and (
            body.disabled is True or (body.role is not None and body.role != "admin"))
        if loses_admin and not _other_active_admins(conn, user_id):
            raise HTTPException(409, "This is the only active admin. Make someone else an admin first.")
        if body.disabled is True and user_id == admin["id"]:
            raise HTTPException(409, "You cannot disable your own account")
        changed = {}
        if body.role is not None and body.role != row["role"]:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, user_id))
            changed["role"] = body.role
        if body.email is not None and body.email.lower() != row["email"]:
            _check_unique(conn, None, body.email, except_id=user_id)
            configured = mailer.is_configured(mailer.config(conn))
            # Admins editing their own address stay verified so a mail problem cannot lock them out.
            verified = body.email_verified is True or not configured or user_id == admin["id"]
            conn.execute("UPDATE users SET email = ?, email_verified = ? WHERE id = ?",
                         (body.email.lower(), int(verified), user_id))
            changed["email"] = body.email.lower()
            if not verified:
                _send_verification(conn, request, _user_or_404(conn, user_id), invited_by=admin["username"])
                changed["mail"] = "verification"
            elif configured and user_id == admin["id"]:
                # Their own address needs no verification step, but a confirmation proves mail reaches it.
                mailer.send(conn, "address_added", [body.email], mailer.address_added_email(row["username"], body.email.lower()))
                changed["mail"] = "confirmation"
        elif body.email_verified is not None:
            conn.execute("UPDATE users SET email_verified = ? WHERE id = ?", (int(body.email_verified), user_id))
            changed["email_verified"] = body.email_verified
        if body.password:
            auth.set_password(conn, user_id, body.password)
            changed["password"] = "set by admin"
        if body.disabled is not None and body.disabled != bool(row["disabled"]):
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(body.disabled), user_id))
            if body.disabled:
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            changed["disabled"] = body.disabled
        audit(conn, admin["username"], "user.updated", {"username": row["username"], **changed})
    return {"ok": True, "mail": changed.get("mail", "")}


@router.post("/users/{user_id}/resend-verification")
def users_resend(user_id: int, request: Request, admin=Admin):
    with db() as conn:
        row = _user_or_404(conn, user_id)
        if row["email_verified"]:
            raise HTTPException(409, "This account is already verified")
        try:
            _send_verification(conn, request, row, invited_by=admin["username"])
        except mailer.MailError as exc:
            raise HTTPException(409, str(exc))
        audit(conn, admin["username"], "user.verification_resent", {"username": row["username"]})
    return {"ok": True}


@router.post("/users/{user_id}/send-reset")
def users_send_reset(user_id: int, request: Request, admin=Admin):
    with db() as conn:
        row = _user_or_404(conn, user_id)
        if not row["email"]:
            raise HTTPException(409, "This user has no email address")
        token = auth.issue_token(conn, user_id, "reset")
        try:
            mailer.send(conn, "reset", [row["email"]],
                        mailer.reset_email(row["username"], f"{app_url(conn, request)}/#/reset?token={token}"))
        except mailer.MailError as exc:
            raise HTTPException(409, str(exc))
        audit(conn, admin["username"], "user.reset_sent", {"username": row["username"]})
    return {"ok": True}


@router.delete("/users/{user_id}")
def users_delete(user_id: int, admin=Admin):
    with db() as conn:
        row = _user_or_404(conn, user_id)
        if user_id == admin["id"]:
            raise HTTPException(409, "You cannot delete your own account")
        if row["role"] == "admin" and not row["disabled"] and not _other_active_admins(conn, user_id):
            raise HTTPException(409, "This is the only active admin")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        audit(conn, admin["username"], "user.deleted", {"username": row["username"]})
    return {"ok": True}


# ---------- email settings (admin) ----------

@router.get("/integrations/email")
def email_get(admin=Admin):
    with db() as conn:
        cfg = mailer.config(conn)
        log = [dict(r) for r in conn.execute("SELECT * FROM emails ORDER BY id DESC LIMIT 50")]
    password = cfg.pop("password", "")
    return {"settings": {**cfg, "has_password": bool(password)}, "configured": mailer.is_configured(cfg),
            "admin_email": admin["email"], "log": log}


@router.put("/integrations/email")
def email_save(body: EmailSettings, admin=Admin):
    with db() as conn:
        current = mailer.config(conn)
        cfg = body.model_dump()
        cfg["app_url"] = cfg["app_url"].rstrip("/")
        if cfg["provider"] == "gmail":
            # Gmail only needs the address and an app password; the server details are fixed.
            address = cfg["from_email"].lower()
            cfg.update(host="smtp.gmail.com" if address else "", port=587, security="starttls",
                       username=address, from_email=address, password=cfg["password"].replace(" ", ""))
            if cfg["password"] and not (len(cfg["password"]) == 16 and cfg["password"].isalnum()):
                raise HTTPException(422, "A Gmail app password is 16 letters (shown as four groups of four). "
                                         "Your normal Google password will not work here.")
        # A blank password keeps the saved one, but never carries it to a different server or login.
        if not cfg["password"] and (cfg["host"], cfg["username"]) == (current.get("host"), current.get("username")):
            cfg["password"] = current.get("password", "")
        set_integration(conn, "email", cfg)
        audit(conn, admin["username"], "integration.email_saved", {"host": cfg["host"], "from": cfg["from_email"]})
    return {"ok": True}


@router.post("/integrations/email/test")
def email_test(admin=Admin):
    if not admin["email"]:
        raise HTTPException(409, "Your own account has no email address. Add one under Users first.")
    with db() as conn:
        try:
            mailer.send(conn, "test", [admin["email"]], mailer.test_email(admin["username"]), wait=True)
        except mailer.MailError as exc:
            raise HTTPException(502, f"Could not send: {exc}")
    return {"ok": True, "to": admin["email"]}


# ---------- announcements (admin) and notifications (everyone) ----------

@router.post("/announcements")
def announcement_create(body: AnnouncementBody, admin=Admin):
    if not body.in_app and not body.email:
        raise HTTPException(422, "Choose at least one way to deliver it: in the app or by email")
    roles = AUDIENCES[body.audience]
    with db() as conn:
        emailed = 0
        if body.email:
            recipients = [r["email"] for r in conn.execute(
                "SELECT email, role FROM users WHERE disabled = 0 AND email_verified = 1 AND email != ''")
                if r["role"] in roles]
            try:
                emailed = mailer.send(conn, "announcement", recipients,
                                      mailer.announcement_email(body.title, body.message, body.level, admin["username"],
                                                                body.audience))
            except mailer.MailError as exc:
                raise HTTPException(409, str(exc))
        cur = conn.execute(
            "INSERT INTO notifications (title, body, level, audience, in_app, emailed, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (body.title.strip(), body.message.strip(), body.level, body.audience, int(body.in_app), emailed,
             admin["username"], now()))
        audit(conn, admin["username"], "announcement.created",
              {"title": body.title, "audience": body.audience, "in_app": body.in_app, "emailed": emailed})
    return {"id": cur.lastrowid, "emailed": emailed}


@router.get("/announcements")
def announcement_list(admin=Admin):
    with db() as conn:
        rows = conn.execute(
            "SELECT n.*, (SELECT COUNT(*) FROM notification_reads r WHERE r.notification_id = n.id) AS read_by "
            "FROM notifications n ORDER BY n.id DESC LIMIT 100").fetchall()
        return {"items": [dict(r) for r in rows], "email_configured": mailer.is_configured(mailer.config(conn))}


@router.delete("/announcements/{notification_id}")
def announcement_delete(notification_id: int, admin=Admin):
    with db() as conn:
        cur = conn.execute("DELETE FROM notifications WHERE id = ?", (notification_id,))
        if not cur.rowcount:
            raise HTTPException(404, "Announcement not found")
        audit(conn, admin["username"], "announcement.deleted", {"id": notification_id})
    return {"ok": True}


@router.get("/notifications")
def notifications_list(user=User):
    audiences = ("all", "admins" if user["role"] == "admin" else "analysts")
    with db() as conn:
        rows = conn.execute(
            "SELECT n.id, n.title, n.body, n.level, n.created_by, n.created_at, EXISTS "
            "(SELECT 1 FROM notification_reads r WHERE r.notification_id = n.id AND r.user_id = ?) AS read "
            "FROM notifications n WHERE n.in_app = 1 AND n.audience IN (?, ?) ORDER BY n.id DESC LIMIT 30",
            (user["id"], *audiences)).fetchall()
        return {"items": [dict(r) for r in rows], "unread": unread_count(conn, user)}


@router.post("/notifications/read")
def notifications_read(user=User):
    audiences = ("all", "admins" if user["role"] == "admin" else "analysts")
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO notification_reads (notification_id, user_id) "
            "SELECT id, ? FROM notifications WHERE in_app = 1 AND audience IN (?, ?)", (user["id"], *audiences))
    return {"ok": True}
