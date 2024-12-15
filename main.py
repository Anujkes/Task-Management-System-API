from fastapi import FastAPI, Depends, status, Response, HTTPException
import models
from databaseConnection import engine, get_db
import schemas
from sqlalchemy.orm import session 
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm


app= FastAPI()

#if table is not there it create it and if already nothing do
models.Base.metadata.create_all(engine)
pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
def verify_password(plain_password, hashed_password):
    return pwd_cxt.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        userId: int = payload.get("userId")
        if email is None or userId is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email, userId=userId)
    except InvalidTokenError:
        raise credentials_exception
    return token_data


#REGISTER_USER
@app.post('/user/register',response_model=schemas.NewUser,status_code=status.HTTP_201_CREATED, tags=['Register'])
def register_user(request: schemas.User, db: session = Depends(get_db)):
    hashed_password = pwd_cxt.hash(request.password)
    new_user= models.User(email=request.email, name=request.name, password=hashed_password)
    db.add(new_user)
    db.commit() 
    db.refresh(new_user)
    return new_user

#Get User
@app.get('/profile',response_model=schemas.NewUser, tags=['About'])
def about_user(db: session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    user=db.query(models.User).filter(models.User.id==current_user.userId).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not available")
    return user


#USER LOGIN 
@app.post('/login',status_code=status.HTTP_200_OK, tags=['Login'])
def login(request: OAuth2PasswordRequestForm=Depends(), db: session = Depends(get_db)) -> schemas.Token: 
    user = db.query(models.User).filter(models.User.email==request.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Invalid Credentials")
    
    if not verify_password(request.password,user.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Invalid Credentials")
    
    #generate jwt token
    access_token = create_access_token(data={"email": user.email, "userId": user.id})
    return schemas.Token(access_token=access_token, token_type="bearer")

#ABOUT TASK Things

#CREATE TASK
@app.post('/task',status_code=status.HTTP_201_CREATED, tags=['Task'])
def create_task(request: schemas.Task, db: session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_user)):
    new_task= models.Task(title=request.title,
                           description=request.description, 
                           category=request.category, 
                           due_date=request.due_date,
                           priority=request.priority,
                           user_id=current_user.userId)
    db.add(new_task)
    db.commit() 
    db.refresh(new_task)
    return new_task

#READ All Task
@app.get('/task',status_code=status.HTTP_200_OK, tags=['Task'])
def get_all_task(db: session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_user)):
    tasks=db.query(models.Task).filter(models.Task.user_id==current_user.userId).all() 
    if not tasks:
        return {"No any task found"}
    else:
        return tasks
    
# #READ Task BY ID
# @app.get('/task/{id}',status_code=status.HTTP_200_OK, tags=['Task'])
# def get_task_by_id(id, db: session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_user)):
#     task=db.query(models.Task).filter(models.Task.id==id).first()
#     if not task:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                             detail="No Task found")
#     else:
#         return task
    
#UPDATE 
@app.put('/task/{id}',status_code=status.HTTP_200_OK, tags=['Task'])
def update_task(id,request: schemas.Task, db: session = Depends(get_db),current_user: schemas.TokenData = Depends(get_current_user)):
    task = db.query(models.Task).filter(models.Task.id==id)

    if not task.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Task with id {id} not found")
    elif task.first().user_id != current_user.userId:
         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Task with id {id} not found")
    task.update(request.dict())
    db.commit()
    return 'Updated Successfully'


#DELETE TASK 
@app.delete('/task/{id}',status_code=status.HTTP_200_OK, tags=['Task'])
def delete_task(id, db: session = Depends(get_db), current_user: schemas.TokenData = Depends(get_current_user)):
    task = db.query(models.Task).filter(models.Task.id==id)
    if not task.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Task with id {id} not found")
    elif task.first().user_id != current_user.userId:
         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Task with id {id} not found")
    task.delete(synchronize_session=False)
    db.commit()
    return "Deleted Successfully"


from typing import Optional
from fastapi import Query

# Filter Tasks 
@app.get('/task/filter', status_code=status.HTTP_200_OK, tags=['Task'])
def filter_tasks(
    db: session = Depends(get_db),
    current_user: schemas.TokenData = Depends(get_current_user),
    due_date: Optional[str] = Query(None, description="Filter tasks by due date (YYYY-MM-DD)"),
    priority: Optional[models.PriorityLevel] = Query(None, description="Filter tasks by priority (Low, Medium, High)"),
    category: Optional[str] = Query(None, description="Filter tasks by category"),
):
    query = db.query(models.Task).filter(models.Task.user_id == current_user.userId)

    # Apply filters if query parameters are provided
    if due_date:
        query = query.filter(models.Task.due_date == due_date)
    if priority:
        query = query.filter(models.Task.priority == priority)
    if category:
        query = query.filter(models.Task.category.ilike(f"%{category}%"))

    tasks = query.all()
    if not tasks:
        return {"message": "No tasks found matching the given criteria"}

    return tasks
