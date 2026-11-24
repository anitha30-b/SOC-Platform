"""Keep ORM driver selection consistent with the project's psycopg2 runtime."""
from sqlalchemy.engine import make_url


def sqlalchemy_url(value):
    url = make_url(value)
    # SQLAlchemy 2.1 changed the unspecified PostgreSQL driver to psycopg 3.
    # Our ORM and notification listeners use the pinned psycopg2 package.
    if url.drivername in {"postgres", "postgresql"}:
        return url.set(drivername="postgresql+psycopg2")
    return url


def psycopg2_url(value):
    # Strip only the scheme's SQLAlchemy driver marker. Preserve encoded
    # credentials and query parameters byte-for-byte for libpq consumers.
    for prefix in ("postgresql+psycopg2://", "postgres://"):
        if value.startswith(prefix):
            return "postgresql://" + value[len(prefix):]
    return value
