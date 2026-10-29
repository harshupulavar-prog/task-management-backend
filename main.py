import logging
from time import perf_counter

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text

from database import engine, Base
from router import task
from router import user

from exceptions import (
    TaskNotFoundException,
    task_not_found_handler
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",
       
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



Base.metadata.create_all(bind=engine)

with engine.begin() as connection:
    user_columns = {
        column["name"] for column in inspect(connection).get_columns("users")
    }
    if "phone" not in user_columns:
        connection.execute(text("ALTER TABLE users ADD COLUMN phone VARCHAR"))
    if "role" not in user_columns:
        connection.execute(
            text("ALTER TABLE users ADD COLUMN role VARCHAR NOT NULL DEFAULT 'user'")
        )
    pending_signup_columns = {
        column["name"]
        for column in inspect(connection).get_columns("pending_signups")
    }
    if "role" not in pending_signup_columns:
        connection.execute(
            text(
                "ALTER TABLE pending_signups "
                "ADD COLUMN role VARCHAR NOT NULL DEFAULT 'user'"
            )
        )
logger.info("Database schema initialization complete")


app.include_router(task.router)
app.include_router(user.router)


app.add_exception_handler(
    TaskNotFoundException,
    task_not_found_handler
)


@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
):
    logger.error(
        "Unhandled request error (method=%s, path=%s, error_type=%s)",
        request.method,
        request.url.path,
        type(exc).__name__,
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error"
        }
    )


@app.middleware("http")
async def log_requests(request: Request, call_next):
    started_at = perf_counter()
    logger.info("Request started (method=%s, path=%s)", request.method, request.url.path)
    response = await call_next(request)
    elapsed_ms = (perf_counter() - started_at) * 1000
    log_method = logger.info if response.status_code < 400 else logger.warning
    if response.status_code >= 500:
        log_method = logger.error
    log_method(
        "Request completed (method=%s, path=%s, status=%s, duration_ms=%.1f)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


@app.get("/")
def home():
    return {
        "message": "Welcome to Task API"
    }