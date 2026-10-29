import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from resend.exceptions import ResendError
from sqlalchemy import func
from sqlalchemy.orm import Session

import resend

from auth import SECRET_KEY, create_access_token, get_current_user
from database import get_db
from models.pending_signup import PendingSignup
from models.user import User
from schemas.user import (
    AdminSignupRequest,
    AdminSignupVerification,
    SignupRequest,
    SignupVerification,
    UserCreate,
    UserResponse,
    UserRoleUpdate,
)


router = APIRouter()
logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
OTP_TTL = timedelta(minutes=10)
OTP_RESEND_DELAY = timedelta(seconds=60)
OTP_MAX_ATTEMPTS = 5


def _mask_email(email: str) -> str:
    local, separator, domain = email.partition("@")
    if not separator:
        return "[redacted]"
    return f"{local[:1]}***@{domain}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _hash_otp(email: str, code: str) -> str:
    secret = os.getenv("OTP_SECRET_KEY") or SECRET_KEY
    if not secret:
        logger.error("[OTP] Cannot sign code: OTP_SECRET_KEY and SECRET_KEY are unset")
        raise HTTPException(
            status_code=503,
            detail="OTP signing is not configured",
        )
    return hmac.new(
        secret.encode("utf-8"),
        f"{email}:{code}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _send_signup_otp(email: str, code: str, *, admin_invite: bool = False) -> None:
    api_key = os.getenv("RESEND_API_KEY")
    if not api_key:
        logger.error("[OTP] Email delivery is not configured; RESEND_API_KEY is missing")
        raise HTTPException(
            status_code=503,
            detail="Email delivery is not configured",
        )
    sender = os.getenv("EMAIL_FROM") or "onboarding@resend.dev"
    subject = (
        "Your Task Manager admin invitation"
        if admin_invite
        else "Your Task Manager verification code"
    )
    if admin_invite:
        frontend_url = os.getenv("FRONTEND_BASE_URL", "http://localhost:5173").rstrip("/")
        completion_url = (
            f"{frontend_url}/admin/complete-signup"
            f"?email={quote(email, safe='')}"
        )
        text = (
            "An administrator invited you to create an admin account for Task Manager.\n\n"
            f"Your verification code is {code}. It expires in 10 minutes.\n\n"
            f"Complete setup here: {completion_url}\n"
            "If you were not expecting this invitation, you can ignore this email."
        )
    else:
        text = (
            f"Your Task Manager signup verification code is {code}. "
            "It expires in 10 minutes."
        )

    resend.api_key = api_key
    try:
        logger.info(
            "[OTP] Sending %s email through Resend (sender=%s, recipient=%s)",
            "admin invitation" if admin_invite else "signup verification",
            sender,
            _mask_email(email),
        )
        result = resend.Emails.send(
            {
                "from": sender,
                "to": [email],
                "subject": subject,
                "text": text,
            }
        )
        logger.info(
            "[OTP] Resend accepted %s email (email=%s, email_id=%s)",
            "admin invitation" if admin_invite else "signup verification",
            _mask_email(email),
            result.get("id", "unknown") if isinstance(result, dict) else "unknown",
        )
    except ResendError as error:
        diagnostic = str(error.message)
        for sensitive_value in (api_key, email, code):
            if sensitive_value:
                diagnostic = diagnostic.replace(sensitive_value, "[redacted]")
        logger.warning(
            "[OTP] Resend rejected %s email (status=%s, type=%s, sender=%s, recipient=%s, detail=%s)",
            "admin invitation" if admin_invite else "signup verification",
            error.code,
            error.error_type,
            sender,
            _mask_email(email),
            diagnostic,
        )
        if str(error.code) == "403":
            logger.warning(
                "[OTP] Resend returned 403; check that EMAIL_FROM uses a verified domain "
                "and that the recipient is allowed for the current Resend account"
            )
        raise HTTPException(
            status_code=502,
            detail="Email delivery failed",
        ) from error
    except Exception as error:
        logger.error(
            "[OTP] Resend request failed unexpectedly (error_type=%s, sender=%s, recipient=%s)",
            type(error).__name__,
            sender,
            _mask_email(email),
        )
        raise HTTPException(
            status_code=502,
            detail="Email delivery failed",
        ) from error


def _require_admin(
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        logger.warning("[AUTHZ] Admin access denied: authenticated account not found")
        raise HTTPException(status_code=401, detail="User not found")
    if user.role != "admin":
        logger.warning(
            "[AUTHZ] Admin access denied (user_id=%s, role=%s)",
            user.id,
            user.role,
        )
        raise HTTPException(status_code=403, detail="Admin access required")
    logger.info("[AUTHZ] Admin access granted (user_id=%s)", user.id)
    return user


@router.post("/signup", status_code=202)
def request_signup_otp(
    signup: SignupRequest,
    db: Session = Depends(get_db),
):
    masked_email = _mask_email(signup.email)
    logger.info("[OTP] Email signup code requested (email=%s)", masked_email)
    if db.query(User).filter(func.lower(User.email) == signup.email).first():
        logger.warning("[OTP] Signup rejected: account already exists (email=%s)", masked_email)
        raise HTTPException(status_code=400, detail="Email already registered")

    now = _utc_now()
    pending = (
        db.query(PendingSignup)
        .filter(PendingSignup.email == signup.email)
        .first()
    )
    if pending and pending.role != "user":
        logger.warning(
            "[OTP] Public signup rejected because an admin invitation is pending (email=%s)",
            masked_email,
        )
        raise HTTPException(
            status_code=409,
            detail="An admin invitation is pending for this email. Use the invitation email to complete setup.",
        )
    if pending and now - pending.last_sent_at < OTP_RESEND_DELAY:
        logger.warning("[OTP] Resend throttled (email=%s)", masked_email)
        raise HTTPException(
            status_code=429,
            detail="Please wait before requesting another code",
        )

    if len(signup.password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 bytes or less")

    code = f"{secrets.randbelow(1_000_000):06d}"
    if pending is None:
        pending = PendingSignup(email=signup.email, phone="", role="user")
        db.add(pending)

    pending.phone = ""
    pending.role = "user"
    pending.hashed_password = pwd_context.hash(signup.password)
    pending.otp_hash = _hash_otp(signup.email, code)
    pending.expires_at = now + OTP_TTL
    pending.last_sent_at = now
    pending.failed_attempts = 0

    logger.info("[OTP] Sending verification email (email=%s)", masked_email)
    _send_signup_otp(signup.email, code)
    db.commit()
    logger.info(
        "[OTP] Verification code issued; expires in %s minutes (email=%s)",
        int(OTP_TTL.total_seconds() // 60),
        masked_email,
    )
    return {"message": "Verification code sent"}


@router.post(
    "/admin/signup",
    status_code=202,
)
def request_admin_signup_otp(
    signup: AdminSignupRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(_require_admin),
):
    masked_email = _mask_email(signup.email)
    logger.info(
        "[OTP] Admin signup invitation requested (admin_id=%s, invited_email=%s)",
        admin.id,
        masked_email,
    )
    if db.query(User).filter(func.lower(User.email) == signup.email).first():
        logger.warning(
            "[OTP] Admin invitation rejected: account already exists (email=%s)",
            masked_email,
        )
        raise HTTPException(status_code=400, detail="Email already registered")

    now = _utc_now()
    pending = (
        db.query(PendingSignup)
        .filter(PendingSignup.email == signup.email)
        .first()
    )
    if pending and pending.role != "admin":
        logger.warning(
            "[OTP] Admin invitation rejected: regular signup pending (email=%s)",
            masked_email,
        )
        raise HTTPException(
            status_code=409,
            detail="A regular signup is already pending for this email. Complete it before inviting as admin.",
        )
    if pending and now - pending.last_sent_at < OTP_RESEND_DELAY:
        logger.warning("[OTP] Admin invitation resend throttled (email=%s)", masked_email)
        raise HTTPException(
            status_code=429,
            detail="Please wait before requesting another code",
        )

    code = f"{secrets.randbelow(1_000_000):06d}"
    if pending is None:
        pending = PendingSignup(email=signup.email, phone="", role="admin")
        db.add(pending)

    pending.phone = ""
    pending.hashed_password = ""
    pending.role = "admin"
    pending.otp_hash = _hash_otp(signup.email, code)
    pending.expires_at = now + OTP_TTL
    pending.last_sent_at = now
    pending.failed_attempts = 0

    logger.info("[OTP] Sending admin invitation email (email=%s)", masked_email)
    _send_signup_otp(signup.email, code, admin_invite=True)
    db.commit()
    logger.info(
        "[OTP] Admin invitation code issued; expires in %s minutes (email=%s)",
        int(OTP_TTL.total_seconds() // 60),
        masked_email,
    )
    return {"message": "Admin invitation sent"}


@router.post(
    "/admin/signup/verify",
    response_model=UserResponse,
    status_code=201,
)
def verify_admin_signup_otp(
    verification: AdminSignupVerification,
    db: Session = Depends(get_db),
):
    masked_email = _mask_email(verification.email)
    logger.info("[OTP] Admin invitation verification submitted (email=%s)", masked_email)
    pending = (
        db.query(PendingSignup)
        .filter(PendingSignup.email == verification.email)
        .first()
    )
    if pending is None or pending.role != "admin":
        logger.warning(
            "[OTP] Admin invitation verification rejected: no pending invitation (email=%s)",
            masked_email,
        )
        raise HTTPException(
            status_code=400,
            detail="Request an admin invitation before completing setup",
        )

    _validate_signup_otp(pending, verification, db)
    if db.query(User).filter(func.lower(User.email) == verification.email).first():
        db.delete(pending)
        db.commit()
        logger.warning(
            "[OTP] Admin invitation rejected: account already exists (email=%s)",
            masked_email,
        )
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=pending.email,
        phone=None,
        hashed_password=pwd_context.hash(verification.password),
        role="admin",
    )
    db.add(user)
    db.delete(pending)
    db.commit()
    db.refresh(user)
    logger.info("[OTP] Admin invitation verified; admin account created (email=%s)", masked_email)
    return user


def _validate_signup_otp(
    pending: PendingSignup,
    verification: SignupVerification,
    db: Session,
) -> None:
    masked_email = _mask_email(verification.email)
    now = _utc_now()
    if pending.expires_at <= now:
        db.delete(pending)
        db.commit()
        logger.warning("[OTP] Verification rejected: code expired (email=%s)", masked_email)
        raise HTTPException(
            status_code=400,
            detail="Verification code expired. Request a new one.",
        )
    if pending.failed_attempts >= OTP_MAX_ATTEMPTS:
        logger.warning("[OTP] Verification locked after maximum attempts (email=%s)", masked_email)
        raise HTTPException(
            status_code=429,
            detail="Too many incorrect codes. Request a new one.",
        )
    if not hmac.compare_digest(
        pending.otp_hash,
        _hash_otp(verification.email, verification.code),
    ):
        pending.failed_attempts += 1
        db.commit()
        logger.warning(
            "[OTP] Verification rejected: incorrect code (attempt %s of %s, email=%s)",
            pending.failed_attempts,
            OTP_MAX_ATTEMPTS,
            masked_email,
        )
        raise HTTPException(status_code=400, detail="Invalid verification code")


@router.post("/signup/verify", response_model=UserResponse, status_code=201)
def verify_signup_otp(
    verification: SignupVerification,
    db: Session = Depends(get_db),
):
    masked_email = _mask_email(verification.email)
    logger.info("[OTP] Verification submitted (email=%s)", masked_email)
    pending = (
        db.query(PendingSignup)
        .filter(PendingSignup.email == verification.email)
        .first()
    )
    if pending is None:
        logger.warning("[OTP] Verification rejected: no pending signup (email=%s)", masked_email)
        raise HTTPException(
            status_code=400,
            detail="Request a verification code before creating your account",
        )

    if pending.role != "user":
        logger.warning(
            "[OTP] Public verification rejected: admin invitation pending (email=%s)",
            masked_email,
        )
        raise HTTPException(
            status_code=409,
            detail="This email has an admin invitation. Complete setup using the invitation link.",
        )

    _validate_signup_otp(pending, verification, db)
    if db.query(User).filter(func.lower(User.email) == verification.email).first():
        db.delete(pending)
        db.commit()
        logger.warning("[OTP] Verification rejected: account already exists (email=%s)", masked_email)
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=pending.email,
        phone=None,
        hashed_password=pending.hashed_password,
        role="user",
    )
    db.add(user)
    db.delete(pending)
    db.commit()
    db.refresh(user)
    logger.info("[OTP] Signup verified; regular user account created (email=%s)", masked_email)
    return user


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=201,
)
def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(_require_admin),
):
    masked_email = _mask_email(user.email)
    logger.info(
        "[AUTH] Admin user creation requested (admin_id=%s, email=%s)",
        admin.id,
        masked_email,
    )
    if len(user.password.encode("utf-8")) > 72:
        logger.warning("[AUTH] Admin user creation rejected: password exceeds allowed length")
        raise HTTPException(
            status_code=400,
            detail="Password must be 72 bytes or less",
        )
    if db.query(User).filter(func.lower(User.email) == user.email).first():
        logger.warning(
            "[AUTH] Admin user creation rejected: account already exists (email=%s)",
            masked_email,
        )
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user.email,
        hashed_password=pwd_context.hash(user.password),
        role="user",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info(
        "[AUTH] User account created by admin (user_id=%s, admin_id=%s, email=%s)",
        new_user.id,
        admin.id,
        masked_email,
    )
    return new_user


@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    email = form_data.username.strip().lower()
    masked_email = _mask_email(email)
    logger.info("[AUTH] Login attempt (email=%s)", masked_email)

    user = db.query(User).filter(func.lower(User.email) == email).first()

    if user is None:
        logger.warning(
            "[AUTH] Login failed: account not found (email=%s)",
            masked_email,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if len(form_data.password.encode("utf-8")) > 72:
        logger.warning(
            "[AUTH] Login failed: password exceeds allowed length (email=%s)",
            masked_email,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not pwd_context.verify(form_data.password, user.hashed_password):
        logger.warning(
            "[AUTH] Login failed: password mismatch (email=%s)",
            masked_email,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(user.email)
    logger.info(
        "[AUTH] Login successful (email=%s, role=%s)",
        masked_email,
        user.role,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
        },
    }


@router.get(
    "/admin/users",
    response_model=list[UserResponse],
)
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(_require_admin),
):
    users = db.query(User).order_by(User.id).all()
    logger.info("[AUTHZ] User list returned (admin_id=%s, count=%s)", admin.id, len(users))
    return users


@router.patch(
    "/admin/users/{user_id}/role",
    response_model=UserResponse,
)
def update_user_role(
    user_id: int,
    update: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(_require_admin),
):
    logger.info(
        "[AUTHZ] Role change requested (admin_id=%s, target_user_id=%s, role=%s)",
        admin.id,
        user_id,
        update.role,
    )
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        logger.warning(
            "[AUTHZ] Role change rejected: target user not found (admin_id=%s, target_user_id=%s)",
            admin.id,
            user_id,
        )
        raise HTTPException(status_code=404, detail="User not found")

    if user.role == "admin" and update.role != "admin":
        admin_count = db.query(User).filter(User.role == "admin").count()
        if admin_count <= 1:
            logger.warning(
                "[AUTHZ] Role change rejected: cannot demote last admin (admin_id=%s, target_user_id=%s)",
                admin.id,
                user_id,
            )
            raise HTTPException(
                status_code=400,
                detail="At least one admin account must remain",
            )

    user.role = update.role
    db.commit()
    db.refresh(user)
    logger.info(
        "[AUTHZ] Role changed (admin_id=%s, target_user_id=%s, role=%s)",
        admin.id,
        user.id,
        user.role,
    )
    return user
