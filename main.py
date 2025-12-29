from datetime import datetime, timedelta,timezone
from typing import Optional,Dict,Any

from fastapi import FastAPI,HTTPException,Depends,status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from jose import jwt,JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr


app = FastAPI(title="FastAPI Auth (JWT)")

# --- Security Settings ---
SECRET_KEY = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# --- Fake DB (in-memory) ---
# email -> user record
users_db: Dict[str, Dict[str, Any]] = {}


# --- Pydantic models ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    email: EmailStr
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# --- Helper functions ---
def hash_password(password: str) -> str:
    try:
        return pwd_context.hash(password)
    except Exception as e:
        print(f"Hash error: {e}")  # Debug için
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password hashing failed: {str(e)}"
        )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(*, subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        subject = payload.get("sub")
        if not subject:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return subject
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="ınvalid or expired token")

def get_user_by_email(email: str):
    return users_db.get(email.lower())


# --- Routes ---
@app.post("/auth/register", response_model=UserPublic, status_code=201)
def register(user: UserCreate):
    email = user.email.lower().strip()
    if get_user_by_email(email):
        raise HTTPException(status_code=409, detail="Email already registered")
    

    users_db[email] = {
        "email": email,
        "password_hash": hash_password(user.password),
        "created_at": datetime.now(timezone.utc),
    }
    return UserPublic(email=email, created_at=users_db[email]["created_at"])


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):

    email = form_data.username.lower().strip()
    user = get_user_by_email(email)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    

    token = create_access_token(
        subject=email,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(access_token=token)


def get_current_user_email(token: str = Depends(oauth2_scheme)) -> str:
    email = decode_token(token)
    if not get_user_by_email(email):
        raise HTTPException(status_code=401, detail="User not found")
    return email


@app.get("/me", response_model=UserPublic)
def me(email: str = Depends(get_current_user_email)):
    u = get_user_by_email(email)
    return UserPublic(email=u["email"], created_at=u["created_at"])