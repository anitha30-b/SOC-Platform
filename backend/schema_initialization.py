"""Register every ORM table before explicitly creating or checking the schema.

Importing the application never performs DDL. This is a bootstrap helper, not a
replacement for reviewing versioned migrations when upgrading an existing DB.
"""
import importlib

from sqlalchemy import inspect, text

from database import Base, engine


MODEL_MODULES = (
    "models", "assets_router", "asset_groups_router", "server_monitor",
    "agent_health_router", "incident",
)


def register_models():
    for name in MODEL_MODULES:
        importlib.import_module(name)
    # Resolve FK targets now, before any CREATE statements are emitted.
    for table in Base.metadata.tables.values():
        for foreign_key in table.foreign_keys:
            foreign_key.column
    return Base.metadata


def initialize_database(bind=None):
    target = engine if bind is None else bind
    metadata = register_models()
    with target.begin() as connection:
        metadata.create_all(bind=connection)
        # Preserve the one existing compatibility adjustment, after its table
        # has been registered and created. Other upgrades use SQL migrations.
        columns = {column["name"] for column in inspect(connection).get_columns("soc_assets")}
        if "url" not in columns:
            connection.execute(text("ALTER TABLE soc_assets ADD COLUMN url VARCHAR(2048)"))


def verify_database_schema(bind=None):
    target = engine if bind is None else bind
    metadata = register_models()
    with target.connect() as connection:
        inspector = inspect(connection)
        missing = sorted(set(metadata.tables) - set(inspector.get_table_names()))
        if missing:
            raise RuntimeError(
                "Database schema is not initialized. Run deployment/initialize_database.py "
                "against the intended database before starting the API. Missing tables: "
                + ", ".join(missing)
            )
        if "url" not in {item["name"] for item in inspector.get_columns("soc_assets")}:
            raise RuntimeError("soc_assets.url is missing; review and apply the schema bootstrap/migrations.")
