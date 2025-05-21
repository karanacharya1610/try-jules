import uuid
from fastapi import APIRouter, Form, HTTPException, Response, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import COOKIE_EXPIRE_SECONDS, COOKIE_DOMAIN, COOKIE_SAMESITE
from app.dependencies import logger
from app.database import get_db
from app.crud.users import insert_user, get_user
from app.crud.codes import get_code, update_code
from app.services.generate_code import generate_code
from app.services.send_code import send_code
from app.services.auth_utils.create_token import create_token
from app.services.validate_email import is_valid_email
from app.services.eventgrid_service import publish_event

router = APIRouter()


@router.post("/auth/signup")
async def signup_handler(name: str = Form(), email: str = Form(), organization: str = Form(default=None), db_session: AsyncSession = Depends(get_db)):
    email = email.lower()
    if not await is_valid_email(email):
        logger.warning("Invalid email provided.", extra={"email": email})
        raise HTTPException(status_code=403, detail="Invalid email.")
    # Check if the email already exists
    user = await get_user(db_session, email)
    if user is not None:
        logger.warning(f"Signup attempt with existing email.", extra={"email": email})
        raise HTTPException(
            status_code=409, detail="Email already exists."
        )  # Raise an exception if email exists

    code = await generate_code(db_session, email, "auth")
    await send_code(email, code, "verification")
    # await publish_event(event_type="User.OTPGenerated", subject=f"user/{email}", data={"email": email, "otp": code, "action": "signup"})

    logger.info("Verification code sent.", extra={"email": email})
    return {"status_code": 200, "message": "Code sent", "email": email, "name": name, "organization": organization}


@router.post("/auth/signup/validate")
async def signup_validate_handler(
    response: Response, name: str = Form(), email: str = Form(), organization: str = Form(default=None), code: str = Form(), db_session: AsyncSession = Depends(get_db)
):
    email = email.lower()
    if not await is_valid_email(email):
        logger.warning("Invalid email provided.", extra={"email": email})
        raise HTTPException(status_code=403, detail="Invalid email.")
    
    if len(code) != 4:
        logger.warning("Invalid code provided.", extra={"email": email, "code": code})
        raise HTTPException(status_code=403, detail="Invalid code.")
    
    result = await get_code(db_session, email, code)
    if result is None:
        logger.warning("Invalid code provided.", extra={"email": email})
        raise HTTPException(status_code=403, detail="Invalid code.")

    await update_code(db_session, email, code, "Used")

    userid = str(uuid.uuid4())
    hashed_password = "hashed_password"  # temporary

    await insert_user(db_session, userid, name, email, hashed_password, organization)
    await db_session.commit()
    access_token = await create_token({"sub": email})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=COOKIE_EXPIRE_SECONDS,
        samesite=COOKIE_SAMESITE,
        secure=True,
        domain=COOKIE_DOMAIN
    )
    user = await get_user(db_session, email)
    await publish_event(event_type="User.SignUp", subject=f"signup/{email}", data={"email": email, "name": name})
    logger.info("User created and logged in", extra={"email": email})
    return user


@router.post("/auth/login")
async def login_handler(email: str = Form(), db_session: AsyncSession = Depends(get_db)):
    email = email.lower()
    if not await is_valid_email(email):
        logger.warning("Invalid email provided.", extra={"email": email})
        raise HTTPException(status_code=403, detail="Invalid email.")

    user = await get_user(db_session, email)
    if user is None:
        logger.warning("Login attempt with non-existing email", extra={"email": email})
        raise HTTPException(status_code=400, detail="Email does not exist. Please sign up.")

    code = await generate_code(db_session, email, "auth")
    await send_code(email, code, "auth")
    # await publish_event(event_type="User.OTPGenerated", subject=f"user/{email}", data={"email": email, "otp": code, "action": "login"})

    logger.info("Authentication code sent", extra={"email": email})
    return {"status_code": 200, "message": "Code sent", "email": email}


@router.post("/auth/login/validate")
async def login_validate_handler(response: Response, email: str = Form(), code: str = Form(), db_session: AsyncSession = Depends(get_db)):
    email = email.lower()
    if not await is_valid_email(email):
        logger.warning("Invalid email provided.", extra={"email": email})
        raise HTTPException(status_code=403, detail="Invalid email.")
    
    if len(code) != 4:
        logger.warning("Invalid code provided.", extra={"email": email, "code": code})
        raise HTTPException(status_code=403, detail="Invalid code.")
    
    result = await get_code(db_session, email, code)
    if result is None:
        logger.warning("Invalid code provided.", extra={"email": email})
        raise HTTPException(status_code=403, detail="Invalid code.")

    await update_code(db_session, email, code, "Used")
    await db_session.commit()

    access_token = await create_token({"sub": email})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=COOKIE_EXPIRE_SECONDS,
        samesite=COOKIE_SAMESITE,
        secure=True,
        domain=COOKIE_DOMAIN
    )
    logger.info("User logged in", extra={"email": email})
    user = await get_user(db_session, email)
    return user


@router.post("/auth/logout")
async def logout_handler(response: Response):
    response.set_cookie(
        key="access_token",
        value="",
        httponly=True,
        max_age=0,
        samesite=COOKIE_SAMESITE,
        secure=True,
        domain=COOKIE_DOMAIN
    )
    logger.info("User logged out")
    return {"message": "Logged out"}
