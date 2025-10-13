import os
import io
import uuid
import pathlib
import tarfile
import contextlib

from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URI")
if not DATABASE_URL:
    DB_PATH = pathlib.Path(__file__).parents[2].joinpath("app.db")
    DATABASE_URL = f"sqlite:///{DB_PATH.resolve()}"


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class JWK(Base):
    __tablename__ = "jwks"
    issuer = Column(String, primary_key=True, index=True)
    pem = Column(Text, nullable=False)


class ProvisioningNonce(Base):
    __tablename__ = "provisioning_nonces"
    nonce = Column(String, primary_key=True, index=True)
    droplet_id = Column(Integer, nullable=False)


class OAuthToken(Base):
    __tablename__ = "oauth_tokens"
    actx = Column(String, primary_key=True, index=True)
    token = Column(Text, nullable=False)


class RbacGitRepo(Base):
    __tablename__ = "rbac_git_repos"
    actx = Column(String, primary_key=True, index=True)
    api = Column(String, index=True)
    repo_data = Column(LargeBinary, nullable=False)


@contextlib.contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_jwk_pem(issuer: str, key_as_pem: str):
    with get_db() as db:
        db_jwk = JWK(issuer=issuer, pem=key_as_pem)
        db.add(db_jwk)
        db.commit()


def get_jwk_pem(issuer: str) -> str | None:
    with get_db() as db:
        db_jwk = db.query(JWK).filter(JWK.issuer == issuer).first()
        if not db_jwk:
            return None
        return db_jwk.pem


def create_provisioning_nonce(nonce: str, droplet_id: int):
    with get_db() as db:
        db_nonce = ProvisioningNonce(nonce=nonce, droplet_id=droplet_id)
        db.add(db_nonce)
        db.commit()


def get_provisioning_nonce_droplet_id(nonce: str) -> int:
    with get_db() as db:
        db_nonce = (
            db.query(ProvisioningNonce).filter(ProvisioningNonce.nonce == nonce).first()
        )
        if not db_nonce:
            raise ValueError(f"Nonce {nonce} not found")
        droplet_id = db_nonce.droplet_id
        db.delete(db_nonce)
        db.commit()
        return droplet_id


def save_oauth_token(actx: uuid.UUID, token: str):
    with get_db() as db:
        db_token = OAuthToken(actx=str(actx), token=token)
        db.merge(db_token)
        db.commit()


def get_oauth_token(actx: uuid.UUID) -> str | None:
    with get_db() as db:
        db_token = (
            db.query(OAuthToken).filter(OAuthToken.actx == str(actx)).first()
        )
        if not db_token:
            raise ValueError(f"OAuth token for {actx} not found")
        return db_token.token


def _tar_directory(path: pathlib.Path) -> bytes:
    with io.BytesIO() as tar_buffer:
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            tar.add(path, arcname=path.name)
        return tar_buffer.getvalue()


def _untar_directory(data: bytes, dest_path: pathlib.Path):
    dest_path.mkdir(parents=True, exist_ok=True)
    with io.BytesIO(data) as tar_buffer:
        with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
            tar.extractall(path=dest_path)


def save_rbac_git_repo_from_path(api: str, actx: str, repo_path: pathlib.Path):
    repo_data = _tar_directory(repo_path)
    with get_db() as db:
        repo_entry = RbacGitRepo(actx=str(actx), api=api, repo_data=repo_data)
        db.merge(repo_entry)
        db.commit()


def restore_rbac_git_repo_to_path(
    api: str, actx: str, dest_path: pathlib.Path
) -> bool:
    with get_db() as db:
        repo_entry = (
            db.query(RbacGitRepo)
            .filter(RbacGitRepo.actx == str(actx))
            .filter(RbacGitRepo.api == str(api))
            .first()
        )
        if repo_entry and repo_entry.repo_data:
            _untar_directory(repo_entry.repo_data, dest_path.parent)
            return True
        return False


# TODO Does this work?
Base.metadata.create_all(bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
