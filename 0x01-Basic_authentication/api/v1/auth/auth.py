#!/usr/bin/env python3
"""Auth Module
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Manages the API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Handles authorization
        """
        return False

    def authorization_header(self, request=None) -> str:
        """Authorization header
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Current User
        """
        return None
