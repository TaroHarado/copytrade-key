from dishka import Provider, Scope, provide
from core.environment.config import Settings


class EnvironmentProvider(Provider):
    component = "environment"
    scope = Scope.APP

    @provide
    def get_environment(self) -> Settings:
        return Settings()





