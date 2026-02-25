import os
import uuid
from supabase import create_client, Client
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException , Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

load_dotenv()
url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
JWT_SECRET: str = os.environ.get("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24


supabase: Client = create_client(url, key)

app = FastAPI()
security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── JWT Helpers ──────────────────────────────────────────────────────────────

def create_jwt(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    return decode_jwt(credentials.credentials)

# ── Password Helpers ─────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/alerts")
def read_root():
    response = supabase.table("alerts").select("*").order("created_at", desc=True).execute()
    if response.data is None:
        raise HTTPException(status_code=404, detail="No alerts found")
    return response.data


@app.post("/alerts")
async def create_alert(request: Request):
    body = await request.json()
    title = body.get("title")
    message = body.get("message")
    deadline = body.get("deadline")
    if not title or not message or not deadline:
        raise HTTPException(status_code=400, detail="Missing required fields")
    response = supabase.table("alerts").insert(body).execute()
    if response.data is None:
        raise HTTPException(status_code=500, detail="Failed to create alert")
    return {"message": "Alert created successfully", "data": response.data}


@app.post("/invites")
async def create_invite(request: Request):
    body = await request.json()
    response = supabase.table("invites").insert(body).execute()
    if response.data is None:
        raise HTTPException(status_code=500, detail="Failed to create invite")
    return {
        "message": "Invite created successfully to " + body.get("university_name"),
        "data": response.data
    }


@app.get("/fetchUniversities")
def fetch_universities():
    response = supabase.table("users").select("*").eq("role", "university").execute()
    if response.data is None:
        raise HTTPException(status_code=404, detail="No universities found")
    return response.data

@app.post("/signup")
async def signup(request: Request):
    try:
        body = await request.json()

        if not body.get("email") or not body.get("password") or not body.get("role") or not body.get("name"):
            raise HTTPException(status_code=400, detail="Missing required fields")

        email = body.get("email").strip().lower()

        # Check if email already exists
        existing = supabase.table("users").select("id").eq("email", email).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Email already registered")

        user_id = str(uuid.uuid4())
        hashed_pw = hash_password(body["password"])

        supabase.table("users").insert({
            "id": user_id,
            "email": email,
            "name": body["name"],
            "role": body["role"],
            "password": hashed_pw,           # stored as bcrypt hash
        }).execute()

        return {
            "message": "Signup successful",
            "userId": user_id,           
        }

    except HTTPException:
        raise
    except Exception as e:
        print("Signup error:", e)
        raise HTTPException(status_code=500, detail=f"Signup failed: {str(e)}")


@app.post("/signin")
async def signin(request: Request):
    try:
        body = await request.json()

        if not body.get("email") or not body.get("password"):
            raise HTTPException(status_code=400, detail="Missing credentials")

        email = body.get("email").strip().lower()

        result = (
            supabase
            .table("users")
            .select("id, name, role, email, password")
            .eq("email", email)
            .execute()
        )
        # print(f"SignIn attempt for: {email}")
        
        if not result.data:
            print(f"SignIn failed: User {email} not found")
            raise HTTPException(status_code=401, detail="Invalid email or password")

        user = result.data[0]

        if not verify_password(body["password"], user["password"]):   # bcrypt verify
            print(f"SignIn failed: Password mismatch for user {email}")
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_jwt(user["id"], user["email"], user["role"])

        return {
            "message": "SignIn successful",
            "token": token,                  # JWT returned on signin
            "expires_in": JWT_EXPIRY_HOURS,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user["name"],
                "role": user["role"],
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        print("Signin error:", e)
        raise HTTPException(status_code=500, detail=f"Signin error: {str(e)}")
