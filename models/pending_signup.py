from sqlalchemy import Column, DateTime, Integer, String

from database import Base


class PendingSignup(Base):
    __tablename__ = "pending_signups"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    otp_hash = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_sent_at = Column(DateTime, nullable=False)
    failed_attempts = Column(Integer, nullable=False, default=0)
    role = Column(String, nullable=False, default="user", server_default="user")
