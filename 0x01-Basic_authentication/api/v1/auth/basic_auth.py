#!/usr/bin/env python3
"""basic_auth Module
"""
import binascii
from api.v1.auth.auth import Auth
import base64


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
        except (TypeError, binascii.Error):
            return None

        return decoded_string.decode('utf-8')

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
        
        user_pass = decoded_base64_authorization_header.split(':')

        return (user_pass[0], user_pass[-1])
