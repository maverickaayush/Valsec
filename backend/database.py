from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from config import settings

# Size the SQLAlchemy pool from the configured audit concurrency. API requests
# and Celery audit workers each use short-lived SessionLocal instances, so the
# default five-connection pool can otherwise become a bottleneck under parallel
# configuration audits.
_POOL_SIZE = max(10, settings.MAX_CONCURRENT_AUDITS * 4)
engine = create_engine(
    settings.DATABASE_URL, pool_pre_ping=True,
    pool_size=_POOL_SIZE, max_overflow=_POOL_SIZE,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
