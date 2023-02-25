from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import psycopg2
from jose import JWTError, jwt
import string
import random
import smtplib
from email.message import EmailMessage
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection
conn = psycopg2.connect(
    dbname="online_school",
    user="postgres",
    password="password",
    host="localhost",
    port="5432"
)
cur = conn.cursor()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def generate_password(length=8):
    """Generate a random password of the specified length"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for i in range(length))


def postgres_transaction(func):
    def wrapper(*args, **kwargs):
        try:
            # Start a new transaction
            cur.execute("BEGIN;")

            # Call the wrapped function
            result = func(*args, **kwargs)

            # Commit the transaction
            conn.commit()

            return result

        except psycopg2.Error as e:
            # Roll back the transaction
            conn.rollback()
            print(f"Error: {e}")

        finally:
            cur.close()

    return wrapper


@postgres_transaction
def generate_username():
    cur.execute("SELECT username FROM students")
    students = cur.fetchone()
    while True:
        username = 'st' + ''.join([str(random.randint(0, 9)) for _ in range(7)])
        if students is None:
            return username
        if username not in students:
            print(username)
            return username


class Student(BaseModel):
    first_name: str
    last_name: str
    birth_date: str
    country: str
    address: str
    school: str
    email: str
    mentor_id: str = None


# Endpoints
@postgres_transaction
@app.post("/register")
async def register(student: Student):
    password = generate_password()
    hashed_password = pwd_context.hash(password)
    username = generate_username()
    try:
        cur.execute(
            "INSERT INTO students (first_name, last_name, birth_date, country, address, school, email, password, mentor_id, username) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                student.first_name, student.last_name, student.birth_date, student.country, student.address,
                student.school, student.email, hashed_password, student.mentor_id, username), )
        conn.commit()
        smtp_server = 'smtp.gmail.com'  # Replace with your own SMTP server
        smtp_port = 587  # Replace with the appropriate port for your server
        smtp_username = os.environ.get("EMAIL_ADDRESS")  # Replace with your own email address
        smtp_password = os.environ.get("EMAIL_APP_PASSWORD")  # Replace with your own email password

        message = f'Subject: Your new password for school\n\nYour username: {username}\nYour new password is: {password}'

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(smtp_username, student.email, message)
        return {"message": "Student registered successfully"}
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=400, detail="Email already registered")


@postgres_transaction
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    cur.execute("SELECT * FROM students WHERE username=%s", (username,))
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    hashed_password = row[8]
    if not pwd_context.verify(password, hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": username})
    return {"access_token": access_token, "token_type": "bearer"}


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# test
@postgres_transaction
@app.get("/me")
def read_users_me(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    cur.execute("SELECT * FROM students WHERE username=%s", (username,))
    user = cur.fetchone()
    user = {
        "id": user[0],
        "first_name": user[1],
        "last_name": user[2],
        "birth_date": user[3],
        "country": user[4],
        "address": user[5],
        "school": user[6],
        "email": user[7],
        "password": user[8],
        "mentor_id": user[9],
        "username": user[10]
    }
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    return user
