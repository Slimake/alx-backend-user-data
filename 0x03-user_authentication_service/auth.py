#!/usr/bin/env python3
"""auth Module
"""
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """_hash_password method that takes in a password string
    arguments and returns bytes.
    """
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generate a uuid string
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Implement user registration
        """
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError(f'User {user.email} already exists')
        except NoResultFound:
            password = _hash_password(password)
            user = self._db.add_user(email, password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Implement valid_login method
        Check if email and password are valid login
        """
        try:
            user = self._db.find_user_by(email=email)
            password = password.encode('utf-8')

            if bcrypt.checkpw(password, user.hashed_password):
                return True
            else:
                return False
        except NoResultFound:
            return False
