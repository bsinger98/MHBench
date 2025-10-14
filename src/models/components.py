"""
Reusable component models for cyberrange specifications.

This module contains models for reusable components like users and services
that can be used across different parts of a cyberrange specification.
"""

from typing import List
from pydantic import BaseModel, Field, field_validator
from uuid import UUID, uuid4


class User(BaseModel):
    """User account specification."""

    id: UUID = Field(default_factory=uuid4)
    username: str
    password: str = "perry123"
    is_admin: bool = False
    is_decoy: bool = False
    # SSH keys to other users
    ssh_keys: List[UUID] = Field(default_factory=list)
    home_directory: str = Field(default=None)

    @field_validator("home_directory", mode="before")
    @classmethod
    def set_default_home_directory(cls, v, info):
        """Set default home directory to /home/username/ if not provided."""
        if v is None and info.data.get("username"):
            return f"/home/{info.data['username']}/"
        return v


def create_default_root_user() -> User:
    """Create a default root user with standard configuration."""
    return User(
        username="root",
        password="perry123",
        is_admin=True,
        home_directory="/root",
    )
