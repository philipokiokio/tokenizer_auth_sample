from itsdangerous import URLSafeTimedSerializer, BadTimeSignature, BadSignature
import logging
from jose import ExpiredSignatureError, jwt, JWTError
from datetime import timedelta, datetime
from uuid import UUID
from typing import Optional


LOGGER = logging.getLogger(__name__)


# BLACK_LIST_STORE

BLACK_LIST_STORE = {}

# AUTHENTICATION
SECRET_KEY = "29f035a1984bb1be5cdd9f9b42b3682bd9eefbbeb5bd4f7c9e8820da387a6c3e"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 60 * 7
REFRESH_SECRET_KEY = "ec777333f183cbb861b0afeadba8951b8293ce8f2dc5db4a757f60e0c74aa64760ade7289d9177f8569107af1357ac507ce04f0eaf5d1e36cde6fa15700a3ce8"
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 60 * 7 * 3


# TOP_LEVEL_SIGNER
ITS_DANGEROUS_TOKEN_KEY = "da78437ee4d969e5aa5c64d82a4a419d"
token_signer = URLSafeTimedSerializer(secret_key=ITS_DANGEROUS_TOKEN_KEY)


def sign_token(jwt_token: str) -> str:
    return token_signer.dumps(obj=jwt_token)


def resolve_token(signed_token: str, max_age: int):
    try:
        return token_signer.loads(s=signed_token, max_age=max_age)
    except (BadTimeSignature, BadSignature) as e:
        LOGGER.exception(e)
        raise Exception


def create_access_token(data: dict):
    expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) + datetime.utcnow()
    data.update({"exp": expire})
    return jwt.encode(claims=data, key=SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict):
    expire = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES) + datetime.utcnow()
    data.update({"exp": expire})
    return jwt.encode(claims=data, key=REFRESH_SECRET_KEY, algorithm=ALGORITHM)


def create_top_level_signed_access_token(data: dict):
    expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) + datetime.utcnow()
    data.update({"exp": expire})
    encoded_jwt = jwt.encode(claims=data, key=SECRET_KEY, algorithm=ALGORITHM)
    dangerous_access_token = sign_token(jwt_token=encoded_jwt)

    return dangerous_access_token


def create_top_level_signed_refresh_token(data: dict):
    expire = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES) + datetime.utcnow()
    data.update({"exp": expire})
    encoded_jwt = jwt.encode(claims=data, key=REFRESH_SECRET_KEY, algorithm=ALGORITHM)

    # add signed_token
    dangerous_refresh_token = sign_token(jwt_token=encoded_jwt)
    return dangerous_refresh_token


def verify_access_token(token: str):
    # Ideal implementation use redis to black list token example is the below:
    # cache_token = redis_utils.get_token_blacklist(token=token)
    # if cache_token:
    #     raise HTTPException(detail="black-listed token", status_code=401)

    cached_token = BLACK_LIST_STORE.get(token)
    if cached_token:
        return "Access Blocked, Token Invalidated"

    try:
        payload = jwt.decode(token=token, key=SECRET_KEY, algorithms=[ALGORITHM])

        id: str = payload.get("id")
        if id is None:
            LOGGER.error(f"Decrypted JWT has no id in payload. {payload}")
            # raise the HTTP Exception
            return "token payload error"

        token_uid = UUID(id)
    except (JWTError, ExpiredSignatureError) as e:
        LOGGER.exception(e)
        LOGGER.error("JWT Decryption Error")
        return "jwt token broken"

    return token_uid


def verify_top_signed_access_token(token: str):
    # Ideal implementation use redis to black list token example is the below:
    # cache_token = redis_utils.get_token_blacklist(token=token)
    # if cache_token:
    #     raise HTTPException(detail="black-listed token", status_code=401)

    cached_token = BLACK_LIST_STORE.get(token)
    if cached_token:
        return "Access Blocked, Token Invalidated"

    try:
        jwt_token = resolve_token(
            signed_token=token, max_age=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    except Exception:
        LOGGER.error("Access_token top level signer decrypt failed")
        # raise the HTTP Exception
        return "token broken"

    try:
        payload = jwt.decode(token=jwt_token, key=SECRET_KEY, algorithms=[ALGORITHM])

        id: str = payload.get("id")
        if id is None:
            LOGGER.error(f"Decrypted JWT has no id in payload. {payload}")
            # raise the HTTP Exception
            return "token payload error"

        token_uid = UUID(id)
    except (JWTError, ExpiredSignatureError) as e:
        LOGGER.exception(e)
        LOGGER.error("JWT Decryption Error")
        return "jwt token broken"

    return token_uid


def verify_refresh_token(token: str):
    # cache_token = redis_utils.get_token_blacklist(token=token)
    # if cache_token:
    #     raise HTTPException(detail="black-listed token", status_code=401)

    cached_token = BLACK_LIST_STORE.get(token)
    if cached_token:
        return "Access Blocked, Token Invalidated"

    try:
        payload = jwt.decode(token=token, key=REFRESH_SECRET_KEY, algorithms=ALGORITHM)
        id: str = payload.get("id")
        if id is None:
            return "Payload data corupted"

        token_id = UUID(id)
    except (JWTError, ExpiredSignatureError) as e:
        LOGGER.exception(e)
        return "JWT decrytpion failed"
    return token_id


def verify_top_signed_refresh_token(token: str):
    # cache_token = redis_utils.get_token_blacklist(token=token)
    # if cache_token:
    #     raise HTTPException(detail="black-listed token", status_code=401)
    cached_token = BLACK_LIST_STORE.get(token)
    if cached_token:
        return "Access Blocked, Token Invalidated"

    try:
        jwt_token = resolve_token(
            signed_token=token, max_age=REFRESH_TOKEN_EXPIRE_MINUTES
        )

    except Exception:
        LOGGER.error("Refresh Token top level signer decrypt failed")
        return "Token broken"

    try:
        payload = jwt.decode(
            token=jwt_token, key=REFRESH_SECRET_KEY, algorithms=ALGORITHM
        )
        id: str = payload.get("id")
        if id is None:
            return "Payload data corupted"

        token_id = UUID(id)
    except (JWTError, ExpiredSignatureError) as e:
        LOGGER.exception(e)
        return "JWT decrytpion failed"
    return token_id
