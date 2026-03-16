from logging.config import fileConfig
from pathlib import Path
from typing import Any, cast

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.core.database import Base
from app.module_loader import load_modules
from app.models import user, user_action_log, user_ip_allowlist  # noqa: F401

config = context.config

if config.config_file_name:
    fileConfig(config.config_file_name)

MODULES_DIR = Path(__file__).resolve().parents[1] / "modules"
MODULES = load_modules(MODULES_DIR)
MODULE_METADATA = [metadata for module in MODULES for metadata in module.metadata]

target_metadata = [Base.metadata, *MODULE_METADATA]


def get_url() -> str:
    return settings.DATABASE_URL


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    config.set_main_option("sqlalchemy.url", get_url())
    config_section = cast(dict[str, Any], config.get_section(config.config_ini_section) or {})
    connectable = engine_from_config(
        config_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
