#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.session import Session
from typing import Any, Union, Dict

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Return User object
        """
        user = User()
        user.email = email
        user.hashed_password = hashed_password

        self._session.add(user)
        self._session.commit()

        return user

    def find_user_by(self, **kwargs: Any) -> User:
        """Returns the first row found in the users table as
        filtered by the method’s input arguments.
        """
        try:
            result: Union[User, None] = \
                self._session.query(User).filter_by(**kwargs).first()
        except InvalidRequestError:
            raise InvalidRequestError

        if result is None:
            raise NoResultFound

        return result

    def update_user(self, user_id: str, **kwargs: Dict) -> None:
        """Update the user’s attributes as passed in the method’s arguments
        """
        user = self.find_user_by(id=user_id)

        for key, value in kwargs.items():
            if key not in user.__dict__:
                raise ValueError

            if key == 'email' and key in user.__dict__:
                user.email = value
            elif key == 'hashed_password' and key in user.__dict__:
                user.hashed_password = value
            elif key == 'session_id' and key in user.__dict__:
                user.session_id = value
            elif key == 'reset_token' and key in user.__dict__:
                user.reset_token = value

        self._session.commit()

        return None
