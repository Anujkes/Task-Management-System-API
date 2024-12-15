from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
#database coonnection

SQLALCHAMY_DATABASE_URL = 'postgresql://postgres:Bright#1270@localhost/fastapi'


db_user: str = 'postgres'
db_port: int = 5432
db_host: str = 'localhost'
db_password: str = 'admin9696'

SQLALCHAMY_DATABASE_URL: str = F'postgresql://{db_user}:{db_password}@{db_host}:{db_port}/Task_Management_System'

engine = create_engine(SQLALCHAMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base() 

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()