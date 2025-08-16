# fake_api.py
import os
import random
from datetime import datetime, timedelta
from typing import List, Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer,
                        String, Table, create_engine)
from sqlalchemy.orm import relationship, sessionmaker, Session, declarative_base

# --- Configuração de Segurança (JWT e Senhas) ---
# Em um projeto real, esta chave deve ser secreta e mais complexa!
SECRET_KEY = "uma-chave-super-secreta-para-um-projeto-fake"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Contexto para hashing de senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Esquema de autenticação OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# --- Configuração do Banco de Dados SQLite ---
DATABASE_URL = "sqlite:///./fake_iot.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Tabela de Associação (Muitos-para-Muitos: Usuários <-> Dispositivos) ---
user_device_association = Table(
    'user_device_association', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('device_id', Integer, ForeignKey('devices.id'), primary_key=True)
)


# --- Modelos do Banco de Dados (SQLAlchemy) ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="operator")  # 'admin' ou 'operator'
    is_active = Column(Boolean, default=True)
    # Relação Muitos-para-Muitos
    accessible_devices = relationship("Device", secondary=user_device_association)

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    location = Column(String)
    status = Column(String, default="online")
    readings = relationship("SensorData", back_populates="device", cascade="all, delete-orphan")

class SensorData(Base):
    __tablename__ = "sensor_data"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    sensor_type = Column(String)
    value = Column(Float)
    device = relationship("Device", back_populates="readings")


# --- Schemas da API (Pydantic) ---
class DeviceSchema(BaseModel):
    id: int
    name: str
    location: str
    status: str
    model_config = ConfigDict(from_attributes=True)

class SensorDataSchema(BaseModel):
    id: int
    timestamp: datetime
    sensor_type: str
    value: float
    model_config = ConfigDict(from_attributes=True)

class UserBase(BaseModel):
    email: str
    role: str = "operator"

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: str | None = None
    role: str | None = None
    password: str | None = None
    accessible_device_ids: List[int] | None = None

class UserSchema(UserBase):
    id: int
    is_active: bool
    accessible_devices: List[DeviceSchema] = []
    model_config = ConfigDict(from_attributes=True)
    
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None


# --- Funções Auxiliares de Segurança ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- Configuração da Aplicação FastAPI ---
app = FastAPI(title="Fake IoT API", description="API Falsa para desenvolvimento do frontend com Autenticação")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Dependências de Segurança ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Usuário inativo")
    return current_user

async def get_current_admin_user(current_user: Annotated[User, Depends(get_current_active_user)]):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Acesso negado: Requer privilégios de administrador")
    return current_user


# --- Lógica de Criação e População do Banco de Dados (Atualizada) ---
def populate_db():
    db = SessionLocal()
    if not db.query(User).first():
        print("Banco de dados vazio. Populando com dados falsos...")

        # Dispositivos
        devices = [
            Device(name="Inversor Solar A", location="Telhado Bloco 1", status="online"),
            Device(name="Sensor de Pressão B", location="Fábrica 2", status="offline"),
            Device(name="Medidor de Energia C", location="Painel Elétrico Principal", status="online"),
        ]
        db.add_all(devices)
        db.commit()

        # Usuários
        admin_user = User(
            email="admin@example.com",
            hashed_password=get_password_hash("admin123"),
            role="admin",
            is_active=True
        )
        op_user = User(
            email="operator@example.com",
            hashed_password=get_password_hash("op123"),
            role="operator",
            is_active=True
        )
        # Associa o operador aos dispositivos 1 e 3
        op_user.accessible_devices.append(db.query(Device).filter(Device.id == 1).first())
        op_user.accessible_devices.append(db.query(Device).filter(Device.id == 3).first())
        
        db.add_all([admin_user, op_user])
        db.commit()

        # Dados de Sensores (igual a antes)
        now = datetime.utcnow()
        for device in db.query(Device).all():
            for i in range(72 * 4): # 3 dias, 4 leituras por hora
                timestamp = now - timedelta(minutes=15 * i)
                sensor_type = "power" if "Inversor" in device.name or "Medidor" in device.name else "pressure"
                value = random.uniform(1500.0, 5500.0) if sensor_type == "power" else random.uniform(98.0, 105.0)
                reading = SensorData(device_id=device.id, timestamp=timestamp, sensor_type=sensor_type, value=value)
                db.add(reading)
        db.commit()
        print("População do banco de dados concluída.")
    else:
        print("Banco de dados já existente.")
    db.close()


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    populate_db()


# --- Endpoints da API (Atualizados e Novos) ---
@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Bem-vindo à Fake IoT API. Use /docs para ver a documentação."}


# Endpoint de Autenticação
@app.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoints de Usuários (Protegidos)
@app.get("/api/users/me", response_model=UserSchema, tags=["Users"])
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Retorna os dados do usuário logado."""
    return current_user

@app.post("/api/users", response_model=UserSchema, status_code=status.HTTP_201_CREATED, tags=["Users"])
def create_user(user: UserCreate, db: Session = Depends(get_db), admin: User = Depends(get_current_admin_user)):
    """Cria um novo usuário (somente admin)."""
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email já registrado")
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password, role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.put("/api/users/{user_id}", response_model=UserSchema, tags=["Users"])
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db), admin: User = Depends(get_current_admin_user)):
    """Atualiza um usuário (somente admin)."""
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    if user_update.email:
        db_user.email = user_update.email
    if user_update.role:
        db_user.role = user_update.role
    if user_update.password:
        db_user.hashed_password = get_password_hash(user_update.password)
    if user_update.accessible_device_ids is not None:
        devices = db.query(Device).filter(Device.id.in_(user_update.accessible_device_ids)).all()
        db_user.accessible_devices = devices

    db.commit()
    db.refresh(db_user)
    return db_user

# Endpoints de Dispositivos (Protegidos)
@app.get("/api/devices", response_model=list[DeviceSchema], tags=["Devices"])
def get_devices(current_user: Annotated[User, Depends(get_current_active_user)], db: Session = Depends(get_db)):
    """Retorna dispositivos. Admin vê todos, operador vê apenas os designados."""
    if current_user.role == "admin":
        return db.query(Device).all()
    return current_user.accessible_devices

@app.get("/api/devices/{device_id}", response_model=DeviceSchema, tags=["Devices"])
def get_device(device_id: int, current_user: Annotated[User, Depends(get_current_active_user)], db: Session = Depends(get_db)):
    """Retorna um dispositivo se o usuário tiver permissão."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    if current_user.role == "operator":
        device_ids = [d.id for d in current_user.accessible_devices]
        if device_id not in device_ids:
            raise HTTPException(status_code=403, detail="Acesso negado a este dispositivo")
            
    return device

@app.get("/api/devices/{device_id}/data", response_model=list[SensorDataSchema], tags=["Sensor Data"])
def get_sensor_data(
    device_id: int, 
    current_user: Annotated[User, Depends(get_current_active_user)],
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    db: Session = Depends(get_db)
):
    """Retorna dados de um sensor se o usuário tiver permissão."""
    # Primeiro, verificamos a permissão usando a lógica do endpoint get_device
    get_device(device_id, current_user, db)
    
    query = db.query(SensorData).filter(SensorData.device_id == device_id)
    if start_date:
        query = query.filter(SensorData.timestamp >= start_date)
    if end_date:
        query = query.filter(SensorData.timestamp <= end_date)
    
    return query.order_by(SensorData.timestamp.desc()).limit(1000).all() # Adicionado um limite