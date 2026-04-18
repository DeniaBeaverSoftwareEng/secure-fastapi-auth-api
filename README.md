# Secure FastAPI Authentication API

A security-focused backend API built with FastAPI.

## Features
- JWT authentication
- Access and refresh tokens
- Role-based access control (RBAC)
- Brute-force protection with account lockout
- Security event logging
- Protected user and admin routes

## Tech Stack
- FastAPI
- SQLAlchemy
- SQLite
- python-jose
- bcrypt
- Pydantic

## Endpoints
- POST /register
- POST /login
- POST /refresh
- GET /profile
- GET /admin
- GET /debug-user/{email}
- GET /logs

## Project Focus
This project was built to practice real backend security patterns beyond basic CRUD, including token handling, account lockout, role protection, and audit logging.
