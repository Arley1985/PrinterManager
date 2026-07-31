import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from ipaddress import ip_network
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
SECRET_KEY = os.environ.get("SECRET_KEY")
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


class DiscoveredPrinter(BaseModel):
    ip: str
    open_ports: list[int]
    web_url: str | None = None


PRINTER_PORTS = (80, 443, 515, 631, 9100)


def get_connection():
    connection = psycopg2.connect(DATABASE_URL)
    return connection


def init_db() -> None:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS printers (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    ip TEXT NOT NULL UNIQUE,
                    brand TEXT NOT NULL,
                    location TEXT NOT NULL
                )
                """
            )
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                hashed = pwd_context.hash("admin123")
                cursor.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
                    ("admin", hashed, 1),
                )
        connection.commit()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str):
    with get_connection() as connection:
        with connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT id, username, password_hash, is_admin FROM users WHERE username = %s",
                (username,),
            )
            return cursor.fetchone()


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
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

    user = get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user


def require_admin(user: Annotated[dict, Depends(get_current_user)]):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Se requiere administrador")
    return user


def is_port_open(ip: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_host(ip: str) -> DiscoveredPrinter | None:
    open_ports = [port for port in PRINTER_PORTS if is_port_open(ip, port)]
    if not open_ports:
        return None

    web_url = None
    if 80 in open_ports:
        web_url = f"http://{ip}"
    elif 443 in open_ports:
        web_url = f"https://{ip}"

    return DiscoveredPrinter(ip=ip, open_ports=open_ports, web_url=web_url)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.post("/api/auth/register", response_model=User, status_code=201)
def register(user_in: UserIn):
    if get_user(user_in.username):
        raise HTTPException(status_code=409, detail="Usuario ya existe")
    hashed = pwd_context.hash(user_in.password)
    with get_connection() as connection:
        with connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s) RETURNING id, username, is_admin",
                (user_in.username.strip(), hashed, 1 if user_in.is_admin else 0),
            )
            new_user = cursor.fetchone()
        connection.commit()
        return new_user


@app.post("/api/auth/login", response_model=Token)
def login(user_in: UserIn) -> Token:
    user = get_user(user_in.username)
    if not user or not verify_password(user_in.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    access_token = create_access_token({"sub": user["username"]})
    return Token(access_token=access_token)


@app.get("/api/auth/me", response_model=User)
def me(user: Annotated[dict, Depends(get_current_user)]):
    return user


@app.get("/api/printers", response_model=list[Printer])
def list_printers(user: Annotated[dict, Depends(get_current_user)]):
    with get_connection() as connection:
        with connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(
                "SELECT id, name, ip, brand, location FROM printers ORDER BY id DESC"
            )
            return cursor.fetchall()


@app.post("/api/printers", response_model=Printer, status_code=201)
def create_printer(
    printer: PrinterIn, user: Annotated[dict, Depends(require_admin)]
):
    try:
        with get_connection() as connection:
            with connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    "INSERT INTO printers (name, ip, brand, location) VALUES (%s, %s, %s, %s) RETURNING id, name, ip, brand, location",
                    (printer.name.strip(), printer.ip.strip(), printer.brand, printer.location.strip()),
                )
                new_printer = cursor.fetchone()
            connection.commit()
            return new_printer
    except psycopg2.IntegrityError as exc:
        connection.rollback()
        raise HTTPException(status_code=409, detail="Ya existe una impresora con esa IP.") from exc


@app.delete("/api/printers/{printer_id}", status_code=204)
def delete_printer(
    printer_id: int, user: Annotated[dict, Depends(require_admin)]
):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM printers WHERE id = %s", (printer_id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Impresora no encontrada")
        connection.commit()


@app.get("/api/scan", response_model=list[DiscoveredPrinter])
def scan_network(
    network: str, user: Annotated[dict, Depends(get_current_user)]
) -> list[DiscoveredPrinter]:
    try:
        parsed_network = ip_network(network, strict=False)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail="Rango de red invalido. Usa formato CIDR, ejemplo: 192.168.1.0/24"
        ) from exc

    if parsed_network.num_addresses > 1024:
        raise HTTPException(
            status_code=400, detail="El rango es muy grande. Usa /22, /23 o /24 para escanear por zonas."
        )

    hosts = [str(host) for host in parsed_network.hosts()]
    found: list[DiscoveredPrinter] = []

    with ThreadPoolExecutor(max_workers=80) as executor:
        futures = [executor.submit(scan_host, host) for host in hosts]
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda item: tuple(int(part) for part in item.ip.split(".")))


