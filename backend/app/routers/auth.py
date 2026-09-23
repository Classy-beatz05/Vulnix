from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models, schemas, auth
from app.database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


def _log(db: Session, request: Request, user_id: str, action: str, detail: str = ""):
    db.add(models.AuditLog(
        user_id=user_id,
        ip_address=request.client.host if request.client else None,
        action=action,
        detail=detail,
    ))
    db.commit()


@router.post("/signup", response_model=schemas.UserOut, status_code=201)
def signup(payload: schemas.UserCreate, request: Request, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")
    user = models.User(email=payload.email, hashed_password=auth.hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    _log(db, request, user.id, "signup")
    return user


@router.post("/login", response_model=schemas.Token)
def login(payload: schemas.UserCreate, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not auth.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = auth.create_access_token(subject=user.id)
    _log(db, request, user.id, "login")
    return schemas.Token(access_token=token)


@router.get("/me", response_model=schemas.UserOut)
def me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user
