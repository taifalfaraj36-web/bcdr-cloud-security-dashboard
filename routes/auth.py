from fastapi import APIRouter, HTTPException
from models.auth_model import LoginRequest

router = APIRouter()

users_db = {
    "admin": {"password": "admin123", "role": "Admin"},
    "auditor": {"password": "audit123", "role": "Auditor"}
}

fake_tokens = {
    "admin": "admin-token-123",
    "auditor": "auditor-token-123"
}

@router.post("/login")
def login(data: LoginRequest):
    user = users_db.get(data.username)

    if user and user["password"] == data.password:
        return {
            "message": "Login successful",
            "user": data.username,
            "role": user["role"],
            "token": fake_tokens[data.username]
        }

    raise HTTPException(status_code=401, detail="Invalid username or password")