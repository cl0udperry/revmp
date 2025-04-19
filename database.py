from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

#1. Database URL: default to SQLite for development, configurable for PostgreSQL
SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

#3. SessionLocal for session management
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

#4. Base model class for ORM models
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()