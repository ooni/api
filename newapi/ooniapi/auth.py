"""
Authentication API
"""
from datetime import datetime, timedelta
from email.headerregistry import Address
from email.message import EmailMessage
from urllib.parse import urljoin
import hashlib
import re
import smtplib

from flask import Blueprint, current_app, request, make_response
from flask.json import jsonify
import jwt  # debdeps: python3-jwt

from ooniapi.config import metrics

# from ooniapi.utils import cachedjson

auth_blueprint = Blueprint("auth_api", "auth")

"""
Browser authentication - see probe_services.py for probe authentication
Requirements:
  - Never store users email address nor IP addresses nor passwords
  - Verify email to limit spambots. Do not use capchas
  - Support multiple sessions / devices, ability to register/login again

Workflow:
  Explorer:
    - call register_user using an email and receive a temporary login link
    - call login_user and receive a long-lived cookie
    - call <TODO> using the previous email to get a new temp. login link
    - call the citizenlab CRUD entry points using the cookie
    - call bookmarked searches/urls/msmts entry points using the cookie
"""

# Courtesy of https://emailregex.com/
EMAIL_RE = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")


def jerror(msg, code=400):
    return make_response(jsonify(error=msg), code)


def create_jwt(payload: dict) -> str:
    key = current_app.config["JWT_ENCRYPTION_KEY"]
    return jwt.encode(payload, key, algorithm="HS256").decode()


def decode_jwt(token, **kw):
    key = current_app.config["JWT_ENCRYPTION_KEY"]
    return jwt.decode(token, key, algorithms=["HS256"], **kw)


def hash_email_address(email_address: str) -> str:
    key = current_app.config["JWT_ENCRYPTION_KEY"].encode()
    em = email_address.encode()
    return hashlib.blake2b(em, key=key, digest_size=16).hexdigest()


def _send_email(dest_addr: str, msg: EmailMessage) -> None:
    log = current_app.logger
    conf = current_app.config
    smtphost = conf["MAIL_SERVER"]
    port = conf["MAIL_PORT"]
    mail_user = conf["MAIL_USERNAME"]
    mail_password = conf["MAIL_PASSWORD"]
    use_ssl = conf["MAIL_USE_SSL"]
    log.debug(f"connecting to {smtphost}:{port} as {mail_user}")
    SMTP = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    try:
        with SMTP(host=smtphost, port=port) as s:
            s.ehlo()
            s.login(mail_user, mail_password)
            s.send_message(msg)
    except Exception as e:
        log.error(e, exc_info=1)
        raise


def send_login_email(dest_addr, nick, token: str) -> None:
    """Format and send a registration/login  email"""
    src_addr = current_app.config["MAIL_SOURCE_ADDRESS"]
    baseurl = current_app.config["BASE_URL"]
    url = urljoin(baseurl, f"/api/v1/user_login?k={token}")

    msg = EmailMessage()
    msg["Subject"] = "OONI Account activation"
    msg["From"] = Address(src_addr)
    msg["To"] = (Address(dest_addr),)

    txt = f"""Welcome to OONI, {nick}.

    Please login by following {url}

    The link can be used on multiple devices and will expire in 24 hours.
    """
    msg.set_content(txt)
    html = f"""\
<html>
  <head></head>
  <body>
    <p>Welcome to OONI, {nick}</p>
    <p>
        <a href="{url}">Please login here </a>
    </p>
    <p>The link can be used on multiple devices and will expire in 24 hours.</p>
  </body>
</html>
"""
    msg.add_alternative(html, subtype="html")
    _send_email(dest_addr, msg)


@metrics.timer("register_user")
@auth_blueprint.route("/api/v1/register_user", methods=["POST"])
def register_user():
    """Auth Services: start email-based user registration
    ---
    parameters:
      - in: body
        name: register data
        description: Registration data as HTML form or JSON
        required: true
        schema:
          type: object
          properties:
            nickname:
              type: string
            email_address:
              type: string
    responses:
      200:
        description: Confirmation
    """
    log = current_app.logger
    req = request.json if request.is_json else request.form
    nick = req.get("nickname", "").strip()
    # Accept all alphanum including unicode and whitespaces
    if not nick.replace(" ", "").isalnum():
        return jerror("Invalid user name")
    if len(nick) < 3:
        return jerror("User name is too short")
    if len(nick) > 50:
        return jerror("User name is too long")

    email_address = req.get("email_address", "").strip().lower()
    if not nick or not email_address:
        return jerror("Invalid request")
    if EMAIL_RE.fullmatch(email_address) is None:
        return jerror("Invalid email address")

    account_id = hash_email_address(email_address)
    now = datetime.utcnow()
    expiration = now + timedelta(days=1)
    # On the backend side the registration is stateless
    payload = {
        "nbf": now,
        "exp": expiration,
        "aud": "register",
        "account_id": account_id,
        "nick": nick,
    }
    registration_token = create_jwt(payload)
    log.info("sending registration token")
    try:
        send_login_email(email_address, nick, registration_token)
        log.info("email sent")
    except Exception as e:
        log.error(e, exc_info=1)
        return jerror("Unable to send the email")

    return make_response(jsonify(msg="ok"), 200)


@metrics.timer("user_login")
@auth_blueprint.route("/api/v1/user_login", methods=["GET"])
def user_login():
    """Probe Services: login using a registration/login link
    ---
    parameters:
      - name: k
        in: query
        type: string
        description: JWT token with aud=register
    responses:
      200:
        description: Login response, set cookie
    """
    log = current_app.logger
    token = request.args.get("k", "")
    try:
        dec = decode_jwt(token, audience="register")
    except jwt.exceptions.MissingRequiredClaimError:
        return jerror("Invalid token type", code=401)
    except jwt.exceptions.InvalidSignatureError:
        return jerror("Invalid credential signature", code=401)
    except jwt.exceptions.DecodeError:
        return jerror("Invalid credentials", code=401)

    log.info("user login successful")
    now = datetime.utcnow()
    payload = {
        "nbf": now,
        "iat": now,
        "aud": "user_auth",
        "account_id": dec["account_id"],
        "nick": dec["nick"],
    }
    token = create_jwt(payload)
    r = make_response(jsonify(token=token), 200)
    r.set_cookie("ooni", token, secure=True, httponly=True, samesite="Strict")
    return r


"""
CREATE TABLE IF NOT EXISTS accounts (
    account_id text PRIMARY KEY,
    role text
);

GRANT SELECT ON TABLE accounts TO amsapi;
GRANT SELECT ON TABLE accounts TO readonly;

CREATE TABLE IF NOT EXISTS account_expunge (
    account_id text PRIMARY KEY,
    threshold timestamp without time zone NOT NULL
);
GRANT SELECT ON TABLE public.account_expunge TO amsapi;
GRANT SELECT ON TABLE public.account_expunge TO readonly;
"""


@auth_blueprint.route("/api/v1/set_account_role", methods=["POST"])
def set_account_role():
    """Set a role to a given account identified by an email address
    ---
    parameters:
      - in: body
        name: email address and role
        description: data as HTML form or JSON
        required: true
        schema:
          type: object
          properties:
            email_address:
              type: string
            role:
              type: string
    responses:
      200:
        description: Confirmation
    """
    log = current_app.logger
    req = request.json if request.is_json else request.form
    role = req.get("role", "").strip().lower()
    email_address = req.get("email_address", "").strip().lower()
    if EMAIL_RE.fullmatch(email_address) is None:
        return jerror("Invalid email address")
    if role not in ["user", "admin"]:
        return jerror("Invalid role")

    account_id = hash_email_address(email_address)
    log.info(f"Giving account {account_id} role {role}")
    query = """INSERT INTO accounts (account_id, role)
        VALUES(:account_id, :role)
        ON CONFLICT (account_id) DO
        UPDATE SET role = EXCLUDED.role
    """
    query_params = dict(account_id=account_id, role=role)
    q = current_app.db_session.execute(query, query_params).rowcount
    log.info(f"Role set {q}")
    current_app.db_session.commit()
    return ""


@auth_blueprint.route("/api/v1/get_account_role/<email_address>")
def get_account_role(email_address):
    """Get account role. Return an empty string if the account is not found.
    ---
    parameters:
      - name: email_address
        in: path
        required: true
        type: string
    """
    log = current_app.logger
    email_address = email_address.strip().lower()
    if EMAIL_RE.fullmatch(email_address) is None:
        return jerror("Invalid email address")
    account_id = hash_email_address(email_address)
    query = "SELECT role FROM accounts WHERE account_id = :account_id"
    query_params = dict(account_id=account_id)
    q = current_app.db_session.execute(query, query_params)
    r = q.fetchone()
    if r:
        role = r[0]
        log.info(f"Getting account {account_id} role: {role}")
        return role
    else:
        log.info(f"Getting account {account_id} role: not found")
        return ""
