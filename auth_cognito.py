import jwt
from jwt import PyJWKClient
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer

AWS_REGION = "eu-west-1"
USER_POOL_ID = "eu-west-1_ToQpGDLc8"
APP_CLIENT_ID = "451a5hf6nd4btsiiftmi039hfv"

ISSUER = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{USER_POOL_ID}"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"

security = HTTPBearer()
jwks_client = PyJWKClient(JWKS_URL)


def verify_token(credentials=Security(security)):
    token = credentials.credentials

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},
        )

        return decoded

    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


def require_admin(user=Depends(verify_token)):
    groups = user.get("cognito:groups", [])

    if "Admin" not in groups:
        raise HTTPException(
            status_code=403,
            detail="Access denied. Admin role required."
        )

    return user


def require_admin_or_auditor(user=Depends(verify_token)):
    groups = user.get("cognito:groups", [])

    if "Admin" not in groups and "Auditor" not in groups:
        raise HTTPException(
            status_code=403,
            detail="Access denied. Admin or Auditor role required."
        )

    return user