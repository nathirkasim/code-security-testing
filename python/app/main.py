import os
import sqlite3
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from app.security_utils import hash_password, verify_password, safe_resolve_path


app = FastAPI(
    title="Clean Baseline Service",
    description="Security-hardened baseline REST API",
    version="1.0.0",
)


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: str = Field(..., max_length=100, pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    password: str = Field(..., min_length=12, max_length=128)


class UserResponse(BaseModel):
    id: int
    username: str
    email: str


def get_db_connection() -> sqlite3.Connection:
    db_path = os.getenv("DATABASE_PATH", ":memory:")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
    conn.close()


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.get("/health", status_code=status.HTTP_200_OK)
def health_check() -> dict:
    return {"status": "healthy", "service": "clean-baseline"}


@app.get("/ready", status_code=status.HTTP_200_OK)
def readiness_check() -> dict:
    return {"status": "ready"}


@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate) -> UserResponse:
    salt_hex, hash_hex = hash_password(user.password)

    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute(
                "INSERT INTO users (username, email, salt, password_hash) VALUES (?, ?, ?, ?)",
                (user.username, user.email, salt_hex, hash_hex),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered.",
        )
    conn.close()

    return UserResponse(id=user_id, username=user.username, email=user.email)


@app.get("/users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: int) -> UserResponse:
    conn = get_db_connection()
    cursor = conn.execute(
        "SELECT id, username, email FROM users WHERE id = ?",
        (user_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    return UserResponse(id=row["id"], username=row["username"], email=row["email"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
