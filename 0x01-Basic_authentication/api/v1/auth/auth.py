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
        if path is None:
            return True
        elif excluded_paths is None or len(excluded_paths) == 0:
            return True

        if path.endswith('/'):
            pass
        else:
            path = path[:] + '/'

        if path in excluded_paths:
            return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """Authorization header
        """
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """Current User
        """
        return None
