from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from typing import List


app = FastAPI()

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    hashed_password = Column(String)

    def verify_password(self, plain_password):
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        return pwd_context.verify(plain_password, self.hashed_password)

engine = create_engine("postgresql://postgres:pgadmin123@localhost/taxi_wars")
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
session = Session()
Base.metadata.create_all(bind=engine)

security = HTTPBasic()

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = session.query(User).filter(User.username == credentials.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not user.verify_password(credentials.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return user

@app.post("/users/", response_model=User)
def create_user(username: str, password: str):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash(password)
    user = User(username=username, hashed_password=hashed_password)
    session.add(user)
    session.commit()
    return user

@app.put("/users/{user_id}", response_model=User)
def update_user(user_id: int, username: str = None, password: str = None, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="You don't have permission to update this user")
    kwargs = {}
    if username is not None:
        kwargs["username"] = username
    if password is not None:
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = pwd_context.hash(password)
        kwargs["hashed_password"] = hashed_password
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for key, value in kwargs.items():
        setattr(user, key, value)
    session.commit()
    return user

@app.delete("/users/{user_id}", response_model=User)
def delete_user(user_id: int, current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="You don't have permission to delete this user")
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return user

@app.get("/users/{user_id}", response_model=User)
def read_user(user_id: int):
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/palindrome")
def check_palindrome(items: List[str],User = Depends(get_current_user)):
    max_items = 6  
    s = "".join(items[:max_items])  
    if s == s[::-1]:  
        return {"message": f"{s} is a palindrome!"}
    else:
        return {"message": f"{s} is not a palindrome."}