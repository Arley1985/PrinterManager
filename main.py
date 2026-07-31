import os
import traceback
from datetime import datetime, timedelta
from typing import Annotated

import psycopg2
import psycopg2.extras
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret-key-for-development")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

app = FastAPI(title="Gestor de Impresoras Universidad")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UserIn(BaseModel):
    username: Annotated[str, Field(min_length=3, max_length=50)]
    password: Annotated[str, Field(min_length=6, max_length=100)]
    is_admin: bool = False


class User(BaseModel):
    id: int
    username: str
    is_admin: bool


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PrinterIn(BaseModel):
    name: Annotated[str, Field(min_length=2, max_length=80)]
    ip: Annotated[str, Field(min_length=7, max_length=45)]
    brand: Annotated[str, Field(pattern="^(HP|Kyocera|Ricoh|Otra)$")]
    location: Annotated[str, Field(min_length=2, max_length=100)]


class Printer(PrinterIn):
    id: int


def get_db_url():
    url = DATABASE_URL
    if not url:
        raise Exception("DATABASE_URL not configured")
    url = url.replace("pgbouncer=true", "").replace("&&", "&").replace("?&", "?")
    if url.endswith("?"):
        url = url[:-1]
    if url.endswith("&"):
        url = url[:-1]
    if "sslmode" not in url:
        url += "&sslmode=require" if "?" in url else "?sslmode=require"
    return url


def get_connection():
    return psycopg2.connect(get_db_url())


def ensure_tables():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS printers (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    ip TEXT NOT NULL UNIQUE,
                    brand TEXT NOT NULL,
                    location TEXT NOT NULL
                )
            """)
            cur.execute("SELECT COUNT(*) FROM users")
            if cur.fetchone()[0] == 0:
                hashed = pwd_context.hash("admin123")
                cur.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
                    ("admin", hashed, 1),
                )
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    try:
        ensure_tables()
    except Exception as e:
        print(f"DB init error: {e}")
        traceback.print_exc()


@app.get("/", include_in_schema=False)
def index():
    return {"message": "PrinterManager API is running", "docs": "/docs"}


@app.post("/api/auth/register", response_model=User, status_code=201)
def register(user_in: UserIn):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (user_in.username.strip(),))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Usuario ya existe")
            hashed = pwd_context.hash(user_in.password)
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s) RETURNING id, username, is_admin",
                (user_in.username.strip(), hashed, 1 if user_in.is_admin else 0),
            )
            new_user = cur.fetchone()
        conn.commit()
        return new_user
    finally:
        conn.close()


@app.post("/api/auth/login", response_model=Token)
def login(user_in: UserIn):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, username, password_hash, is_admin FROM users WHERE username = %s",
                (user_in.username.strip(),),
            )
            user = cur.fetchone()
        if not user or not verify_password(user_in.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Credenciales invalidas")
        access_token = create_access_token({"sub": user["username"]})
        return Token(access_token=access_token)
    finally:
        conn.close()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)]
):
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Token invalido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalido o expirado")

    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, username, is_admin FROM users WHERE username = %s",
                (username,),
            )
            user = cur.fetchone()
    finally:
        conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user


def require_admin(user: Annotated[dict, Depends(get_current_user)]):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Se requiere administrador")
    return user


@app.get("/api/auth/me", response_model=User)
def me(user: Annotated[dict, Depends(get_current_user)]):
    return user


@app.get("/api/printers", response_model=list[Printer])
def list_printers(user: Annotated[dict, Depends(get_current_user)]):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, name, ip, brand, location FROM printers ORDER BY id DESC")
            return cur.fetchall()
    finally:
        conn.close()


@app.post("/api/printers", response_model=Printer, status_code=201)
def create_printer(printer: PrinterIn, user: Annotated[dict, Depends(require_admin)]):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "INSERT INTO printers (name, ip, brand, location) VALUES (%s, %s, %s, %s) RETURNING id, name, ip, brand, location",
                (printer.name.strip(), printer.ip.strip(), printer.brand, printer.location.strip()),
            )
            new_printer = cur.fetchone()
        conn.commit()
        return new_printer
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Ya existe una impresora con esa IP.")
    finally:
        conn.close()


@app.delete("/api/printers/{printer_id}", status_code=204)
def delete_printer(printer_id: int, user: Annotated[dict, Depends(require_admin)]):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM printers WHERE id = %s", (printer_id,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Impresora no encontrada")
        conn.commit()
    finally:
        conn.close()
