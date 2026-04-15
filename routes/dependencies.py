from fastapi import Header, HTTPException

VALID_TOKENS = [
    "admin-token-123",
    "auditor-token-123"
]

def verify_token(x_token: str = Header(None)):
    if x_token not in VALID_TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized access")