import os
import re
import secrets
from datetime import datetime, timedelta
from typing import Optional

import dns.resolver
from fastapi import FastAPI, Depends, HTTPException, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# ---------------- CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hosting.db")
SITES_DIR = os.path.join(BASE_DIR, "sites")
NGINX_CONFIG_DIR = os.path.join(BASE_DIR, "nginx-configs")
HOST_PUBLIC = os.environ.get("HOST_PUBLIC", "http://localhost:5000")
JWT_SECRET = os.environ.get("HOST_JWT_SECRET", "change_me_random_secret_please")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
TOKEN_PREFIX = "fastapi-verify="

os.makedirs(SITES_DIR, exist_ok=True)
os.makedirs(NGINX_CONFIG_DIR, exist_ok=True)

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

class Domain(Base):
    __tablename__ = "domains"
    id = Column(Integer, primary_key=True, index=True)
    site_id = Column(Integer, ForeignKey("sites.id"))
    domain = Column(String, unique=True, index=True)
    token = Column(String)
    verified = Column(Boolean, default=False)
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

def save_nginx_config(domain: str, site_path: str):
    cfg = f"""server {{
    listen 80;
    server_name {domain};
    root {site_path};
    index index.html;
    location / {{
        try_files $uri $uri/ =404;
    }}
}}"""
    fn = os.path.join(NGINX_CONFIG_DIR, f"{domain}.conf")
    with open(fn, "w", encoding="utf-8") as f:
        f.write(cfg)
    return fn

# ---------------- App ----------------
app = FastAPI(title="FastAPI Hosting without Chat")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
  )
# ---------------- Sites ----------------

@app.post("/api/sites/create")
async def api_create_site(name: str = Form(...), title: str = Form(""), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
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
            f.write(f"""<!doctype html><meta charset="utf-8"><title>{slug}</title><h1>✅ {slug} created</h1>""")
    return {"site_id": site.id, "slug": slug, "preview": f"{HOST_PUBLIC}/{slug}/"}

@app.get("/api/sites/my")
def api_my_sites(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sites = db.query(Site).filter(Site.user_id == current_user.id).all()
    result = []
    for s in sites:
        domains = [d.domain for d in db.query(Domain).filter(Domain.site_id == s.id).all()]
        result.append({"id": s.id, "slug": s.slug, "title": s.title, "domains": domains, "preview": f"{HOST_PUBLIC}/{s.slug}/"})
    return result

@app.post("/api/sites/{site_id}/upload")
async def api_upload_file(site_id: int, file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
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

# ---------------- Domains ----------------
@app.post("/api/domains/add")
async def api_add_domain(site_id: int = Form(...), domain: str = Form(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    site = db.query(Site).filter(Site.id == site_id, Site.user_id == current_user.id).first()
    if not site:
        raise HTTPException(404, "Site not found")
    domain = domain.strip().lower()
    if db.query(Domain).filter(Domain.domain == domain).first():
        raise HTTPException(400, "Domain already exists")
    token = secrets.token_hex(12)
    rec = Domain(site_id=site.id, domain=domain, token=token, verified=False)
    db.add(rec)
    db.commit()
    txt = f"{TOKEN_PREFIX}{token}"
    return {"domain": domain, "txt": txt, "example": f"{domain} TXT {txt}"}

@app.get("/api/domains/verify")
def api_verify_domain(domain: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rec = db.query(Domain).filter(Domain.domain == domain).first()
    if not rec:
        raise HTTPException(404, "Domain not found")
    site = db.query(Site).filter(Site.id == rec.site_id).first()
    if not site or site.user_id != current_user.id:
        raise HTTPException(403, "Not allowed")
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=8.0)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    found = any(f"{TOKEN_PREFIX}{rec.token}" in b"".join(r.strings).decode(errors="ignore") for r in answers)
    if not found:
        return {"ok": False, "message": "TXT not found"}
    rec.verified = True
    db.commit()
    site_path = ensure_site_path(site.user_id, site.slug)
    cfg = save_nginx_config(domain, site_path)
    return {"ok": True, "nginx_config_file": cfg}

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
# ---------------- Admin SPA ----------------
ADMIN_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>FastAPI Hosting — Admin Panel</title>
<style>
body{font-family:system-ui, Arial;background:#0f172a;color:#e2e8f0;margin:0;padding:0}
.app{max-width:1100px;margin:20px auto;padding:20px;background:#020617;border-radius:8px}
h1{margin:0 0 12px 0}
.row{display:flex;gap:12px;margin-bottom:12px}
.col{flex:1}
input,textarea,select{width:100%;padding:8px;border-radius:6px;border:1px solid #334155;background:#071129;color:#e2e8f0}
button{padding:8px 12px;border-radius:8px;border:none;background:#2563eb;color:white;cursor:pointer}
small{font-size:13px;color:#94a3b8}
.list{background:#071129;padding:10px;border-radius:6px;max-height:300px;overflow:auto}
pre{background:#020617;padding:12px;border-radius:6px;color:#9ae6b4;overflow:auto;white-space:pre-wrap}
</style>
</head>
<body>
<div class="app">
<h1>FastAPI Hosting — Admin Panel</h1>

<div id="authArea">
  <div id="loginForm">
    <input id="username" placeholder="Username"><br><br>
    <input id="password" type="password" placeholder="Password"><br><br>
    <button onclick="login()">Login</button>
    <small id="loginMsg"></small>
  </div>
</div>

<div id="panelArea" style="display:none;">
  <button onclick="logout()">Logout</button>
  <h2>My Sites</h2>
  <div id="sitesList" class="list"></div>

  <h3>Create New Site</h3>
  <input id="newSiteName" placeholder="Site slug/name">
  <input id="newSiteTitle" placeholder="Site title">
  <button onclick="createSite()">Create</button>

  <h3>Edit Site</h3>
  <select id="editSiteSelect"></select>
  <textarea id="siteEditor" rows="15" placeholder="HTML code here"></textarea><br>
  <button onclick="saveSite()">Save</button>
</div>

<script>
let token = "";
let currentSiteId = null;

function login(){
  fetch("/token", {
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:`username=${document.getElementById('username').value}&password=${document.getElementById('password').value}`
  }).then(r=>r.json()).then(data=>{
    if(data.access_token){
      token=data.access_token;
      document.getElementById('authArea').style.display='none';
      document.getElementById('panelArea').style.display='block';
      loadSites();
    } else {
      document.getElementById('loginMsg').innerText=data.error||"Login failed";
    }
  })
}

function logout(){
  token=""; 
  document.getElementById('panelArea').style.display='none'; 
  document.getElementById('authArea').style.display='block';
}

function loadSites(){
  fetch("/api/sites/my",{headers:{"Authorization":"Bearer "+token}})
  .then(r=>r.json())
  .then(data=>{
    const list = document.getElementById('sitesList');
    const select = document.getElementById('editSiteSelect');
    list.innerHTML=""; select.innerHTML="";
    data.forEach(s=>{
      let div=document.createElement("div");
      div.innerHTML=`<b>${s.slug}</b> — <a href="${s.preview}" target="_blank">Preview</a>`;
      list.appendChild(div);
      let opt=document.createElement("option");
      opt.value=s.id; opt.text=s.slug;
      select.appendChild(opt);
    });
    if(data.length>0){currentSiteId=data[0].id; loadSiteCode();}
  });
}

function createSite(){
  const name=document.getElementById('newSiteName').value;
  const title=document.getElementById('newSiteTitle').value;
  fetch("/api/sites/create",{
    method:"POST",
    headers:{"Authorization":"Bearer "+token},
    body:new URLSearchParams({name:name,title:title})
  }).then(r=>r.json()).then(res=>{
    if(res.ok){loadSites(); alert("Site created!");}
    else{alert(res.error||"Error")}
  });
}

function loadSiteCode(){
  const siteId = document.getElementById('editSiteSelect').value;
  if(!siteId) return;
  currentSiteId = siteId;
  fetch(`/api/sites/my`,{headers:{"Authorization":"Bearer "+token}})
  .then(r=>r.json())
  .then(data=>{
    const site = data.find(s=>s.id==currentSiteId);
    if(site){
      fetch(`/${site.slug}/index.html`).then(r=>r.text()).then(t=>{
        document.getElementById('siteEditor').value=t;
      });
    }
  });
}

document.getElementById('editSiteSelect').addEventListener('change', loadSiteCode);

function saveSite(){
  const code = document.getElementById('siteEditor').value;
  if(!currentSiteId) return;
  const site = document.getElementById('editSiteSelect');
  const slug = site.options[site.selectedIndex].text;
  const blob = new Blob([code], {type:"text/html"});
  const formData = new FormData();
  formData.append("file", new File([blob], "index.html"));
  fetch(`/api/sites/${currentSiteId}/upload`,{
    method:"POST",
    headers:{"Authorization":"Bearer "+token},
    body: formData
  }).then(r=>r.json()).then(res=>{
    if(res.uploaded){alert("Saved!");}
    else{alert(res.error||"Error")}
  });
}
</script>
</div>
</body>
</html>
"""

@app.get("/admin", response_class=HTMLResponse)
def admin_panel():
    return ADMIN_HTML
