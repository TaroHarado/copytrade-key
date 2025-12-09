from typing import Annotated, AsyncIterator

from dishka import FromComponent, provide, Provider, Scope
from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
)
from core.environment.config import Settings


class CopytradingDatabaseConnectionProvider(Provider):
    """Provider для copytrading database (READ-ONLY + replay protection)"""
    component = "copytrading_database"
    scope = Scope.APP

    @provide
    async def get_copytrading_engine(
        self,
        conf: Annotated[Settings, FromComponent("environment")]
    ) -> AsyncEngine:
        """Provides copytrading database engine (READ-ONLY)"""
        engine = create_async_engine(
            url=conf.copytrading_database_url,
            pool_size=2,  # Smaller pool for validation queries
            max_overflow=5,
            pool_timeout=30,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        return engine

    @provide
    async def get_copytrading_session_maker(
        self,
        engine: AsyncEngine,
    ) -> async_sessionmaker[AsyncSession]:
        """Provides session maker for copytrading database"""
        async_session = async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
        return async_session


class CopytradingDatabaseSessionProvider(Provider):
    """Provider для copytrading database sessions"""
    component = "copytrading_database"
    scope = Scope.REQUEST

    @provide
    async def get_copytrading_session(
        self,
        session_maker: Annotated[
            async_sessionmaker[AsyncSession],
            FromComponent("copytrading_database"),
        ],
    ) -> AsyncIterator[AsyncSession]:
        """Provides copytrading database session (READ-ONLY + replay protection)"""
        async with session_maker() as session:
            try:
                yield session
                await session.commit()  # For replay protection updates
            except Exception as e:
                await session.rollback()
                raise e
            finally:
                await session.close()





