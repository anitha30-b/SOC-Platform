import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from database_urls import psycopg2_url, sqlalchemy_url


# Load variables from .env
load_dotenv()


# Get database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in the .env file")


# Pin ORM selection explicitly; leave a libpq-compatible URL for the existing
# psycopg2 notification publishers/listeners that import DATABASE_URL.
SQLALCHEMY_DATABASE_URL = sqlalchemy_url(DATABASE_URL)
DATABASE_URL = psycopg2_url(DATABASE_URL)


# Create database engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True
)


# Create database session
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# Base class for SQLAlchemy models
Base = declarative_base()


# Database dependency for FastAPI
def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
