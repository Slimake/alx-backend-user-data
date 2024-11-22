#!/usr/bin/env python3
"""auth Module
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """_hash_password method that takes in a password string
    arguments and returns bytes.
    """
    password = password.encode('utf-8')
    return bcrypt.hashpw(password, bcrypt.gensalt())
