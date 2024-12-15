# models for database table
from databaseConnection import Base
from sqlalchemy import Column, Integer, String, Enum, ForeignKey
import enum

class PriorityLevel(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

class User(Base):
     __tablename__='User'

     id = Column(Integer, primary_key=True, index=True)
     name = Column(String,nullable=False)
     email = Column(String,nullable=False)
     password = Column(String,nullable=False) 

class Task(Base):
     __tablename__='Task'

     id = Column(Integer, primary_key=True, index=True)
     title = Column(String,nullable=False)
     description = Column(String,nullable=True)
     category = Column(String,nullable=False)
     due_date = Column(String,nullable=False)
     priority = Column(Enum(PriorityLevel), nullable=False)
     user_id = Column(Integer, ForeignKey("User.id"))


