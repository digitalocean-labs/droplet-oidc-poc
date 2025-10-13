import uuid
import contextlib

from . import database


def store_oauth_token(actx: uuid.UUID, token: str) -> None:
    database.save_oauth_token(str(actx), token)


def retrieve_oauth_token(actx: uuid.UUID) -> str | None:
    return database.get_oauth_token(str(actx))
