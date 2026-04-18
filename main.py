from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import jwt, JWTError

import models
import schemas
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    get_current_user,
    SECRET_KEY,
    ALGORITHM,
)
from database import Base, SessionLocal, engine

app = FastAPI()

Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_event(db: Session, email: str, event: str):
    log = models.SecurityLog(
        email=email,
        event_type=event
    )
    db.add(log)
    db.commit()


@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = models.User(
        email=user.email,
        hashed_password=hash_password(user.password),
        role=user.role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == form_data.username).first()

    if not db_user:
        log_event(db, form_data.username, "LOGIN_FAILED_NO_USER")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if db_user.is_locked:
        log_event(db, db_user.email, "LOGIN_BLOCKED_LOCKED")
        raise HTTPException(status_code=403, detail="Account is locked")

    if not verify_password(form_data.password, db_user.hashed_password):
        db_user.failed_attempts += 1

        if db_user.failed_attempts >= 5:
            db_user.is_locked = True
            db.commit()
            db.refresh(db_user)
            log_event(db, db_user.email, "ACCOUNT_LOCKED")
            raise HTTPException(status_code=403, detail="Account locked after too many failed attempts")

        db.commit()
        db.refresh(db_user)
        log_event(db, db_user.email, "LOGIN_FAILED")

        raise HTTPException(status_code=400, detail=f"Invalid credentials ({db_user.failed_attempts})")

    db_user.failed_attempts = 0
    db_user.is_locked = False
    db.commit()
    db.refresh(db_user)

    log_event(db, db_user.email, "LOGIN_SUCCESS")

    access_token = create_access_token(data={"sub": db_user.email})
    refresh_token = create_refresh_token(data={"sub": db_user.email})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@app.post("/refresh")
def refresh_token_endpoint(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        email = payload.get("sub")
        token_type = payload.get("type")

        if not email or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        new_access_token = create_access_token(data={"sub": email})

        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@app.get("/profile")
def profile(current_user: str = Depends(get_current_user)):
    return {"message": f"Welcome {current_user}"}


@app.get("/admin")
def admin_route(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == current_user).first()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if db_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    return {"message": "Welcome Admin"}


@app.get("/debug-user/{email}")
def debug_user(email: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "email": user.email,
        "failed_attempts": user.failed_attempts,
        "is_locked": user.is_locked,
        "role": user.role
    }


@app.get("/logs")
def get_logs(db: Session = Depends(get_db)):
    logs = db.query(models.SecurityLog).order_by(models.SecurityLog.id.desc()).all()

    return [
        {
            "email": log.email,
            "event": log.event_type,
            "timestamp": log.timestamp
        }
        for log in logs
    ]
    from jose import jwt, JWTError
from auth import SECRET_KEY, ALGORITHM

@app.post("/refresh")
def refresh_token_endpoint(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        email = payload.get("sub")
        token_type = payload.get("type")

        if not email or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        new_access_token = create_access_token(data={"sub": email})

        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
        