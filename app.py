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
JWT_SECRET = "supersecret"
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60*24*7
TOKEN_PREFIX = "fastapi-verify="
PUBLIC_URL = "http://examplehost.org"

os.makedirs(SITES_DIR, exist_ok=True)

# ---------------- DB ----------------
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class Site(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    slug = Column(String)
    title = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

class Domain(Base):
    __tablename__ = "domains"
    id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("sites.id"))
    domain = Column(String, unique=True)
    token = Column(String)
    verified = Column(Boolean, default=False)

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

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = int(payload.get("user_id"))
    except JWTError:
        raise HTTPException(401, "Invalid token")
    user = db.query(User).filter(User.id==user_id).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user

# ---------------- Utilities ----------------
def clean_slug(slug: str) -> str:
    slug = slug.strip().lower()
    slug = re.sub(r"[^a-z0-9\-]", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    return slug.strip("-") or "site"

def ensure_site_path(user_id:int, slug:str):
    path = os.path.join(SITES_DIR, f"user_{user_id}", slug)
    os.makedirs(path, exist_ok=True)
    return path

# ---------------- App ----------------
app = FastAPI(title="Simple HTML Hosting")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ---------------- Front Page ----------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <head>
        <meta charset="utf-8">
        <title>ExampleHost.org — Simple Hosting</title>
        <style>
            body{background:#0f172a;color:#e2e8f0;font-family:system-ui;padding:50px;}
            h1{color:#3b82f6;}
            a.button{background:#3b82f6;color:white;padding:10px 20px;text-decoration:none;border-radius:6px;}
            a.button:hover{background:#2563eb;}
        </style>
    </head>
    <body>
        <h1>Welcome to ExampleHost.org</h1>
        <p>Simple HTML hosting with domain verification via TXT and auto-generated URLs.</p>
        <a href="/admin" class="button">Go to Admin Panel</a>
    </body>
    </html>
    """

# ---------------- Registration / Login ----------------
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username==username).first():
        raise HTTPException(400, "Username exists")
    user = User(username=username, password_hash=hash_password(password))
    db.add(user); db.commit(); db.refresh(user)
    return {"ok": True, "username": username}

@app.post("/token")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username==username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"user_id": user.id})
    return {"access_token": token, "token_type": "bearer"}

# ---------------- Admin SPA ----------------
ADMIN_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Admin Panel — ExampleHost</title>
<style>
body{background:#0f172a;color:#e2e8f0;font-family:system-ui;padding:20px;}
input,button{padding:8px;margin:4px;border-radius:6px;}
input{width:200px;}
button{background:#3b82f6;color:white;border:none;cursor:pointer;}
button:hover{background:#2563eb;}
textarea{width:100%;height:150px;margin:4px 0;}
select{padding:6px;}
.list{background:#071129;padding:10px;border-radius:6px;max-height:200px;overflow:auto;}
</style>
</head>
<body>
<h1>Admin Panel</h1>

<div id="authArea">
    <h3>Login / Register</h3>
    <input id="username" placeholder="Username"><br>
    <input id="password" type="password" placeholder="Password"><br>
    <button onclick="login()">Login</button>
    <button onclick="register()">Register</button>
    <p id="msg"></p>
</div>

<div id="panelArea" style="display:none;">
    <button onclick="logout()">Logout</button>
    <h2>My Sites</h2>
    <div id="sitesList" class="list"></div>

    <h3>Create Site</h3>
    <input id="newSiteName" placeholder="Site slug"><button onclick="createSite()">Create</button>

    <h3>Edit Site</h3>
    <select id="siteSelect"></select><br>
    <textarea id="siteCode"></textarea><br>
    <button onclick="saveSite()">Save</button>
</div>

<script>
let token="";
let currentSiteId=null;

function register(){
    fetch("/register",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:`username=${document.getElementById('username').value}&password=${document.getElementById('password').value}`}).then(r=>r.json()).then(r=>{msg.innerText=r.ok?"Registered!":"Error"})
}
function login(){
    fetch("/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:`username=${document.getElementById('username').value}&password=${document.getElementById('password').value}`}).then(r=>r.json()).then(r=>{token=r.access_token;document.getElementById('authArea').style.display="none";document.getElementById('panelArea').style.display="block";loadSites()})
}
function logout(){token="";document.getElementById('authArea').style.display="block";document.getElementById('panelArea').style.display="none"}
function loadSites(){fetch("/sites/my",{headers:{"Authorization":"Bearer "+token}}).then(r=>r.json()).then(data=>{sitesList.innerHTML="";siteSelect.innerHTML="";data.forEach(s=>{let d=document.createElement("div");d.innerText=s.slug;sitesList.appendChild(d);let o=document.createElement("option");o.value=s.id;o.text=s.slug;siteSelect.appendChild(o)});if(data.length>0){currentSiteId=data[0].id;loadSiteCode()}})}
function createSite(){fetch("/sites/create",{method:"POST",headers:{"Authorization":"Bearer "+token},body:new URLSearchParams({name:newSiteName.value})}).then(r=>r.json()).then(r=>loadSites())}
function loadSiteCode(){let id=siteSelect.value;currentSiteId=id;fetch(`/${siteSelect.options[siteSelect.selectedIndex].text}/index.html`).then(r=>r.text()).then(t=>siteCode.value=t)}
function saveSite(){const fd=new FormData();fd.append("file",new File([siteCode.value],"index.html"));fetch(`/sites/${currentSiteId}/upload`,{method:"POST",headers:{"Authorization":"Bearer "+token},body:fd}).then(r=>r.json()).then(r=>alert("Saved!"))}
</script>
</body>
</html>
"""

@app.get("/admin", response_class=HTMLResponse)
def admin():
    return ADMIN_HTML

# ---------------- Serve Sites ----------------
@app.get("/{slug}/{path:path}")
def serve_site(slug,path):
    base=SITES_DIR
    for user_folder in os.listdir(base):
        candidate=os.path.join(base,user_folder,slug,path)
        if os.path.isfile(candidate): return FileResponse(candidate)
    return HTMLResponse("<h1>404 — File not found</h1>",status_code=404)

@app.get("/{slug}/")
def serve_index(slug):
    base=SITES_DIR
    for user_folder in os.listdir(base):
        candidate=os.path.join(base,user_folder,slug,"index.html")
        if os.path.isfile(candidate): return FileResponse(candidate)
    return HTMLResponse("<h1>404 — Index not found</h1>",status_code=404)

# ---------------- Run ----------------
if __name__=="__main__":
    import uvicorn
    uvicorn.run("app:app",host="0.0.0.0",port=5000,reload=True)
