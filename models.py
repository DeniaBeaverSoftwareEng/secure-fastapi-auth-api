from sqlalchemy import Column, Integer, String, Boolean
from datetime import datetime
from database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    failed_attempts = Column(Integer, default=0)
    is_locked = Column(Boolean, default=False)

    role = Column(String, default="user")


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    event_type = Column(String, nullable=False)
    timestamp = Column(String, default=lambda: datetime.utcnow().isoformat())
    