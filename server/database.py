# database.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text, Boolean, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum

DATABASE_URL = "sqlite:///./data/server.db"  # Cambiar a PostgreSQL en producción

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class UserRole(enum.Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(Enum(UserRole), default=UserRole.VIEWER)  # Rol por defecto
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    twofa_secret = Column(String, nullable=True)
    twofa_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Agent(Base):
    __tablename__ = "agents"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    hostname = Column(String)
    ip = Column(String)
    token = Column(String, unique=True, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="offline")
    created_at = Column(DateTime, default=datetime.utcnow)
    executable_hash = Column(String, nullable=True)
    # Relación con auditoría (opcional)
    audit_logs = relationship("AuditLog", back_populates="agent")

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, index=True)  # 0 para eventos locales
    type = Column(String)  # 'log', 'alert'
    level = Column(String)  # 'info', 'warning', 'error'
    module = Column(String)
    message = Column(Text)
    data = Column(JSON, default={})
    timestamp = Column(DateTime, default=datetime.utcnow)

class ModuleData(Base):
    __tablename__ = "module_data"
    id = Column(Integer, primary_key=True, index=True)
    module = Column(String, index=True)
    agent_id = Column(Integer, index=True, nullable=True)
    data = Column(JSON, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=True)
    action = Column(String)  # Ej: "LOGIN", "CONFIGURE_MODULE", "SEND_COMMAND"
    resource = Column(String, nullable=True)  # Ej: "module:waf", "agent:5"
    details = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    agent = relationship("Agent", back_populates="audit_logs")

class ServerSecret(Base):
    __tablename__ = "server_secrets"
    key = Column(String, primary_key=True)
    value = Column(String)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()