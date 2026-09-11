"""Database engine and session management (SQLAlchemy)."""
from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from . import config

connect_args = {"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(config.DATABASE_URL, connect_args=connect_args, future=True)


@event.listens_for(engine, "connect")
def _enforce_sqlite_fk(dbapi_connection, _):
    """Turn ON foreign-key enforcement so the per-target authorisation
    invariant (Ch.5 6.1) is enforced by the data layer, not just the app."""
    if config.DATABASE_URL.startswith("sqlite"):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401  (register models)
    Base.metadata.create_all(bind=engine)
