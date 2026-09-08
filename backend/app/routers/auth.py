from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import get_db
from ..models import User
from ..security import create_access_token, hash_password, verify_password

router = APIRouter()

class Credentials(BaseModel):
    email: EmailStr
    password: str

@router.post("/register")
async def register(data: Credentials, db: AsyncSession = Depends(get_db)):
    email = str(data.email).lower()
    if (await db.execute(select(User).where(User.email == email))).scalar_one_or_none():
        raise HTTPException(409, "Email already registered")
    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"id": user.id, "email": user.email, "access_token": create_access_token(str(user.id)), "token_type": "bearer"}

@router.post("/login")
async def login(data: Credentials, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == str(data.email).lower()))).scalar_one_or_none()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    return {"id": user.id, "email": user.email, "access_token": create_access_token(str(user.id)), "token_type": "bearer"}
