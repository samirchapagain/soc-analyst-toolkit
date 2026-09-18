from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import UserLogin, UserRegister
from app.services.auth_service import create_token, current_user, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
@router.post("/register")
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.scalar(select(User).where((User.email == payload.email.lower()) | (User.username == payload.username))): raise HTTPException(409, "Username or email already registered")
    user = User(username=payload.username, email=payload.email.lower(), hashed_password=hash_password(payload.password), role="analyst")
    db.add(user); db.commit(); db.refresh(user)
    return {"access_token": create_token(user.id, user.email, user.role), "token_type":"bearer", "user":{"id":user.id,"username":user.username,"email":user.email,"role":user.role}}
@router.post("/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == payload.username))
    if not user or not verify_password(payload.password, user.hashed_password): raise HTTPException(401, "Invalid credentials")
    return {"access_token": create_token(user.id, user.email, user.role), "token_type":"bearer"}
@router.get("/me")
def me(user=Depends(current_user)): return user
