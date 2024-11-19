#!/usr/bin/env python3
"""Auth Module
"""
from flask import request
from typing import List, TypeVar
from os import getenv
import fnmatch


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

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if fnmatch.fnmatch(path, excluded_path):
                    return False
            else:
                if path == excluded_path:
                    return False
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

    def session_cookie(self, request=None):
        """Return a cookie value from a request
        """
        if request is None:
            return None
        SESSION_NAME = getenv('SESSION_NAME')

        return request.cookies.get(SESSION_NAME)
