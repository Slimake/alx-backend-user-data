#!/usr/bin/env python3
"""basic_auth Module
"""
import base64
from typing import TypeVar
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """BasicAuth that inherits from Auth
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Extract Base64 part of the authorization_header
        """
        if authorization_header is None:
            return None
        elif not isinstance(authorization_header, str):
            return None
        elif not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Returns the decoded value of a Base64 string
        """
        if base64_authorization_header is None:
            return None
        elif not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_string = base64.b64decode(base64_authorization_header)
            return decoded_string.decode('utf-8')
        except (TypeError, base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Return the user email and password from the Base64 decoded value
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if decoded_base64_authorization_header.find(':') == -1:
            return (None, None)

        dbah = decoded_base64_authorization_header
        user_email = dbah[0:dbah.find(':')]
        user_pwd = dbah[dbah.find(':') + 1:]

        return (user_email, user_pwd)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Return the User instance based on his email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        from models.user import User
        try:
            users = User.search({'email': user_email})
        except KeyError:
            return None

        if not users:
            return None

        if not users[0].is_valid_password(user_pwd):
            return None
        return users[0]

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieve the User instance for a request
        """
        auth = self.authorization_header(request)
        extracted_auth = self.extract_base64_authorization_header(auth)
        if extracted_auth is None:
            return None
        decoded_str = self.decode_base64_authorization_header(extracted_auth)
        if decoded_str is None:
            return None
        user_pass = self.extract_user_credentials(decoded_str)
        if user_pass == (None, None):
            return None
        user = self.user_object_from_credentials(user_pass[0], user_pass[1])
        if user is None:
            return None
        return user
