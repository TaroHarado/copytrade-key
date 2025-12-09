from typing import Annotated, AsyncIterator

from dishka import FromComponent, provide, Provider, Scope
from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
)
from core.environment.config import Settings


class DatabaseConnectionProvider(Provider):
    """Provider для audit logs database"""
    component = "database"
    scope = Scope.APP

    @provide
    async def get_database_engine(
        self,
        conf: Annotated[Settings, FromComponent("environment")]
    ) -> AsyncEngine:
        """Provides database engine for audit logs"""
        engine = create_async_engine(
            url=(
                f"{conf.database_dialect}+asyncpg://{conf.postgres_user}:"
                f"{conf.postgres_password}@{conf.postgres_hostname}:"
                f"{conf.postgres_port}/{conf.postgres_db}"
            ),
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        return engine

    @provide
    async def get_session_maker(
        self,
        engine: AsyncEngine,
    ) -> async_sessionmaker[AsyncSession]:
        """Provides session maker for audit logs database"""
        async_session = async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
        return async_session


class DatabaseSessionProvider(Provider):
    """Provider для audit logs database sessions"""
    component = "database"
    scope = Scope.REQUEST

    @provide
    async def get_session(
        self,
        session_maker: Annotated[
            async_sessionmaker[AsyncSession],
            FromComponent("database"),
        ],
    ) -> AsyncIterator[AsyncSession]:
        """Provides database session for audit logs"""
        async with session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                raise e
            finally:
                await session.close()





