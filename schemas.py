#schemas for response and requests
from pydantic import BaseModel
from typing import Optional
from datetime import date
import models

class User(BaseModel):
    name: str 
    email: str 
    password: str

class NewUser(BaseModel):
    id: int
    name: str 
    email: str 

class Task(BaseModel):
    title: str 
    description: Optional[str] 
    category: str    
    due_date: date 
    priority: models.PriorityLevel

class Login(BaseModel):
    email: str 
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str
    userId: int 
