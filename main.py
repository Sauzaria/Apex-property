from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import os, secrets
from jose import jwt

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DATABASE_URL.startswith("postgresql://"):
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class License(Base):
    __tablename__ = "licenses"
    key = Column(String, primary_key=True, index=True)
    hwid = Column(String, nullable=True)
    owner_name = Column(String, nullable=True)  # ★追加
    activated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)  # ★追加 (Noneなら無期限)
    is_active = Column(Boolean, default=True)

Base.metadata.create_all(bind=engine)
app = FastAPI()

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

class ActivateRequest(BaseModel):
    license_key: str
    hwid: str

class VerifyRequest(BaseModel):
    license_key: str
    hwid: str

def create_token(data: dict):
    expire = datetime.utcnow() + timedelta(days=30)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/api/activate")
def activate(req: ActivateRequest, db: Session = Depends(get_db)):
    lic = db.query(License).filter(License.key == req.license_key).first()
    if not lic or not lic.is_active:
        raise HTTPException(status_code=404, detail="無効なライセンスキーです")
    
    # 有効期限チェック
    if lic.expires_at and lic.expires_at < datetime.utcnow():
        raise HTTPException(status_code=403, detail="このライセンスは有効期限が切れています")

    if lic.hwid is None:
        lic.hwid = req.hwid
        lic.activated_at = datetime.utcnow()
        db.commit()
        return {"status": "activated", "token": create_token({"key": lic.key, "hwid": lic.hwid})}
    
    if lic.hwid == req.hwid:
        return {"status": "already_activated", "token": create_token({"key": lic.key, "hwid": lic.hwid})}
    else:
        raise HTTPException(status_code=403, detail="このライセンスは別のPCで使用されています")

@app.post("/api/verify")
def verify(req: VerifyRequest, db: Session = Depends(get_db)):
    lic = db.query(License).filter(License.key == req.license_key).first()
    if not lic or not lic.is_active:
        raise HTTPException(status_code=404, detail="無効なライセンスです")
    
    # 有効期限チェック
    if lic.expires_at and lic.expires_at < datetime.utcnow():
        raise HTTPException(status_code=403, detail="このライセンスは有効期限が切れています")
    
    if lic.hwid != req.hwid:
        raise HTTPException(status_code=403, detail="HWIDが一致しません")
    
    return {"status": "valid", "token": create_token({"key": lic.key, "hwid": lic.hwid})}

# ★ 管理用API（キー発行 & 使用者一覧取得）
class GenerateRequest(BaseModel):
    owner_name: str
    expires_at: str  # ISO形式 (例: "2026-12-31T23:59:59")
    preset: str = "custom"  # "1day", "1month", "3month", "lifetime", "custom"

@app.post("/api/admin/generate")
def admin_generate(req: GenerateRequest, secret: str, db: Session = Depends(get_db)):
    if secret != "genesis-admin-2026":
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    # キー生成 (例: XXXX-XXXX-XXXX-XXXX)
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    new_key = "-".join(''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4))
    
    # 有効期限の計算
    now = datetime.utcnow()
    if req.preset == "1day":
        exp = now + timedelta(days=1)
    elif req.preset == "1month":
        exp = now + timedelta(days=30)
    elif req.preset == "3month":
        exp = now + timedelta(days=90)
    elif req.preset == "lifetime":
        exp = None
    else:
        exp = datetime.fromisoformat(req.expires_at) if req.expires_at else None
    
    lic = License(
        key=new_key, hwid=None, owner_name=req.owner_name,
        activated_at=None, expires_at=exp, is_active=True
    )
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return {"license_key": lic.key, "owner_name": lic.owner_name, "expires_at": str(lic.expires_at)}

@app.get("/api/admin/list")
def admin_list(secret: str, db: Session = Depends(get_db)):
    if secret != "genesis-admin-2026":
        raise HTTPException(status_code=403, detail="Unauthorized")
    licenses = db.query(License).all()
    return [{
        "key": l.key, "owner_name": l.owner_name, "hwid": l.hwid,
        "activated_at": str(l.activated_at) if l.activated_at else None,
        "expires_at": str(l.expires_at) if l.expires_at else "無期限",
        "is_active": l.is_active
    } for l in licenses]