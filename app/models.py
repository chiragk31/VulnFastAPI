"""
models.py - Pydantic request/response models.
"""
from pydantic import BaseModel
from typing import Optional


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    email: str


class UserListResponse(BaseModel):
    users: list[UserResponse]


class HealthResponse(BaseModel):
    status: str
