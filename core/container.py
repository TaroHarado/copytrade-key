from dishka import make_async_container
from dishka.integrations.fastapi import FastapiProvider

from core.environment.providers import EnvironmentProvider
from core.database.providers import DatabaseConnectionProvider, DatabaseSessionProvider
from core.copytrading_providers import CopytradingDatabaseConnectionProvider, CopytradingDatabaseSessionProvider
from signing.providers import SigningProvider

container = make_async_container(
    FastapiProvider(),
    EnvironmentProvider(),
    DatabaseConnectionProvider(),
    DatabaseSessionProvider(),
    CopytradingDatabaseConnectionProvider(),
    CopytradingDatabaseSessionProvider(),
    SigningProvider()
)





