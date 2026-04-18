from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    role: str = "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

