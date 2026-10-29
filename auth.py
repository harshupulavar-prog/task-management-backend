import os
import logging
from jose import jwt,JWTError
from datetime import datetime, timedelta, timezone
from fastapi import Depends,HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
logger = logging.getLogger(__name__)

security = HTTPBearer() #it is used to read authorization header

def create_access_token(email: str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)

    data = {
        "sub": email,
        "exp": expire
    }

    token = jwt.encode(
        data,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return token

def verify_token(token: str):
    try:
        payload=jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        return payload
    except JWTError as error:
        logger.warning("Bearer token validation failed (%s)", type(error).__name__)
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"

        )
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    token = credentials.credentials

    payload = verify_token(token)

    email = payload.get("sub")

    if email is None:
        logger.warning("Bearer token rejected: subject claim missing")
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    return email
