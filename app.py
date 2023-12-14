from fastapi import Depends, HTTPException, status, FastAPI, Cookie
from fastapi.security import OAuth2AuthorizationCodeBearer
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
import bcrypt
import secrets
from databases import Database
from sqlalchemy import create_engine, Column, String, Integer, MetaData, Table, select
from passlib.context import CryptContext

DATABASE_URL = "sqlite:///./test.db"
database = Database(DATABASE_URL)

metadata = MetaData()

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("github_id", String, unique=True, index=True),
    Column("password_hash", String),
    Column("access_token", String)
)

engine = create_engine(DATABASE_URL)
metadata.create_all(bind=engine)

app = FastAPI()

@app.get("/favicon.ico", include_in_schema=False)
async def get_favicon():
    return FileResponse("static/favicon.ico")

templates = Jinja2Templates(directory="templates")

# Create a password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Adding SessionMiddleware to my FastAPI app
app.add_middleware(SessionMiddleware, secret_key="~g@[Eu3'|NZnJJB3nEL~-sb^D#M(x7,j")

@app.get("/set-session/")
async def set_session(request: Request, authentication_token: str = Cookie(default=None)):
    # Set the session data based on the authentication token from the request
    request.session["authentication_token"] = authentication_token
    
    # Access the updated session data
    session_data = request.session.get("authentication_token")
    
    return {"message": "Session set", "session_data": session_data}

# OAuth 2.0 Authorization Code Bearer scheme configuration
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    tokenUrl="token",
    authorizationUrl="authorize",
)

# OAuth provider configuration (GitHub as an example)
oauth = OAuth()

oauth.register(
    name='github',
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    authorize_client_params=None,
    token_url='https://github.com/login/oauth/access_token',
    token_params=None,
    redirect_uri='http://localhost:8000/login/callback',
    client_kwargs={'scope': 'user'},
)

# Route to handle user registration
@app.post("/register")
async def register(username: str, password: str, request: Request):
    # Validate the submitted data
    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid username or password"
        )

    # Hash the user's password
    hashed_password = pwd_context.hash(password)

    # Check if the user already exists in the database
    existing_user = await database.fetch_one(
        select(users_table.c.github_id).where(users_table.c.github_id == username)
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    # Create a new user with the hashed password
    user = await database.execute(
        users_table.insert().values(
            github_id=username,
            password_hash=hashed_password,
            access_token=secrets.token_urlsafe(),
        )
    )

    # Continue with the registration logic

# Route to render the login page
@app.get("/login-page", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Route to handle post request
@app.post("/login")
async def login(username: str, password: str, request: Request):
    # Validate the submitted data
    if not username or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid username or password")
    
    # Query the database to get the hashed password of the given username
    query = select(users_table.c.password_hash).where(users_table.c.github_id == username)
    stored_password_hash = await database.fetch_val(query)

     # Check if the user exists and compare passwords using passlib
    if not stored_password_hash or not pwd_context.verify(password, stored_password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

# Callback endpoint for handling the redirection after GitHub authorization
@app.route("/login/callback")
async def login_callback(request: Request, code: str = None, state: str = None, session: str = Cookie(None)):
    """
    Callback endpoint where GitHub redirects the user after successful authorization.
    Exchanges the authorization code for an access token.
    """
    token = await oauth.github.authorize_access_token(request)

    # Check if the user is already logged in
    if session:
        return JSONResponse(content={"message": "User is already logged in", "access_token": session})

    # Check if the user already exists in the database
    user = await database.fetch_one(select(users_table).where(users_table.c.github_id == str(token["github_id"])))

        # If the user doesn't exist, create a new user with a secure session token
    if not user:
        access_token = secrets.token_urlsafe()
        hashed_password = pwd_context.hash(access_token)  # Hash the access token for illustration
        user = await database.execute(users_table.insert().values(github_id=str(token["github_id"]), password_hash=hashed_password, access_token=access_token))

    # Store the user's GitHub ID and secure session token in the session cookie
    response = JSONResponse(content={"message": "Successfully authenticated with GitHub", "access_token": user["access_token"]})
    response.set_cookie(key="session", value=user["access_token"])
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
