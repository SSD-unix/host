import os
import re
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, Form, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# ---------------- CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hosting.db")
SITES_DIR = os.path.join(BASE_DIR, "sites")
JWT_SECRET = os.environ.get("HOST_JWT_SECRET", "change_me_random_secret_please")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 дней
TOKEN_PREFIX = "fastapi-verify="

os.makedirs(SITES_DIR, exist_ok=True)

# ---------------- DB ----------------
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Site(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    slug = Column(String, index=True)
    title = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ---------------- Auth ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: int = int(payload.get("user_id"))
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise credentials_exception
    return user

# ---------------- Utilities ----------------
def clean_slug(slug: str) -> str:
    slug = slug.strip().lower()
    slug = re.sub(r"[^a-z0-9\-]", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    return slug.strip("-") or "site"

def ensure_site_path(user_id: int, slug: str) -> str:
    path = os.path.join(SITES_DIR, f"user_{user_id}", slug)
    os.makedirs(path, exist_ok=True)
    return path
# ---------------- App ----------------
app = FastAPI(title="FastAPI Hosting — Admin + Registration")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- Registration / Login ----------------
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username already exists")
    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"ok": True, "username": username}

@app.post("/token")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"user_id": user.id})
    return {"access_token": token, "token_type": "bearer"}

# ---------------- Admin Panel ----------------
ADMIN_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>FastAPI Hosting v1.0 — Admin Panel</title>
<style>
body{font-family:system-ui, Arial;background:#0f172a;color:#e2e8f0;margin:0;padding:0}
.app{max-width:1100px;margin:20px auto;padding:20px;background:#020617;border-radius:8px}
h1{margin:0 0 12px 0}
input,textarea{width:100%;padding:8px;border-radius:6px;border:1px solid #334155;background:#071129;color:#e2e8f0}
button{padding:8px 12px;border-radius:8px;border:none;background:#2563eb;color:white;cursor:pointer}
.list{background:#071129;padding:10px;border-radius:6px;max-height:300px;overflow:auto}
</style>
</head>
<body>
<div class="app">
<h1>Admin Panel</h1>

<div id="authArea">
  <h3>Register</h3>
  <input id="regUsername" placeholder="Username"><br><br>
  <input id="regPassword" type="password" placeholder="Password"><br><br>
  <button onclick="registerUser()">Register</button>
  <small id="regMsg"></small>
  <hr>
  <h3>Login</h3>
  <input id="loginUsername" placeholder="Username"><br><br>
  <input id="loginPassword" type="password" placeholder="Password"><br><br>
  <button onclick="loginUser()">Login</button>
  <small id="loginMsg"></small>
</div>

<div id="panelArea" style="display:none;">
  <h2>Welcome Admin</h2>
  <button onclick="logout()">Logout</button>
</div>

<script>
let token = "";

function registerUser(){
  const username = document.getElementById('regUsername').value;
  const password = document.getElementById('regPassword').value;
  fetch("/register", {
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:`username=${username}&password=${password}`
  }).then(r=>r.json()).then(data=>{
    document.getElementById('regMsg').innerText = data.ok ? "Registered!" : (data.detail || "Error");
  });
}

function loginUser(){
  const username = document.getElementById('loginUsername').value;
  const password = document.getElementById('loginPassword').value;
  fetch("/token", {
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:`username=${username}&password=${password}`
  }).then(r=>r.json()).then(data=>{
    if(data.access_token){
      token = data.access_token;
      document.getElementById('authArea').style.display='none';
      document.getElementById('panelArea').style.display='block';
    } else {
      document.getElementById('loginMsg').innerText = data.detail || "Login failed";
    }
  });
}

function logout(){
  token="";
  document.getElementById('panelArea').style.display='none';
  document.getElementById('authArea').style.display='block';
}
</script>

</div>
</body>
</html>
"""

@app.get("/admin", response_class=HTMLResponse)
def admin_panel():
    return ADMIN_HTML
# ---------------- Sites ----------------
@app.post("/api/sites/create")
async def create_site(name: str = Form(...), title: str = Form(""), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    slug = clean_slug(name)
    if db.query(Site).filter(Site.user_id == current_user.id, Site.slug == slug).first():
        raise HTTPException(400, "Site slug already exists")
    site = Site(user_id=current_user.id, slug=slug, title=title)
    db.add(site)
    db.commit()
    db.refresh(site)
    path = ensure_site_path(current_user.id, slug)
    index_path = os.path.join(path, "index.html")
    if not os.path.exists(index_path):
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(f"<!doctype html><meta charset='utf-8'><title>{slug}</title><h1>✅ {slug} created</h1>")
    return {"site_id": site.id, "slug": slug, "preview": f"/{slug}/"}

@app.get("/api/sites/my")
def my_sites(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sites = db.query(Site).filter(Site.user_id == current_user.id).all()
    return [{"id": s.id, "slug": s.slug, "title": s.title} for s in sites]

@app.post("/api/sites/{site_id}/upload")
async def upload_file(site_id: int, file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    site = db.query(Site).filter(Site.id == site_id, Site.user_id == current_user.id).first()
    if not site:
        raise HTTPException(404, "Site not found")
    site_path = ensure_site_path(current_user.id, site.slug)
    filename = file.filename
    if ".." in filename or filename.startswith("/"):
        raise HTTPException(400, "Invalid filename")
    filepath = os.path.join(site_path, filename)
    with open(filepath, "wb") as f:
        f.write(await file.read())
    return {"uploaded": True, "filename": filename}

# ---------------- Serve Sites ----------------
@app.get("/{slug}/{path:path}")
def serve_slug_path(slug: str, path: str):
    base = SITES_DIR
    for user_folder in os.listdir(base):
        candidate = os.path.join(base, user_folder, slug, path)
        if os.path.isfile(candidate):
            return FileResponse(candidate)
    return HTMLResponse("<h1>404 — File not found</h1>", status_code=404)

@app.get("/{slug}/")
def serve_slug_index(slug: str):
    base = SITES_DIR
    for user_folder in os.listdir(base):
        candidate = os.path.join(base, user_folder, slug, "index.html")
        if os.path.isfile(candidate):
            return FileResponse(candidate)
    return HTMLResponse("<h1>404 — Index not found</h1>", status_code=404)

# ---------------- Run Uvicorn ----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
