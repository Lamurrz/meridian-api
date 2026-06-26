from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    api_host: str = "127.0.0.1"
    api_port: int = 8000
    log_level: str = "info"

    @property
    def neo4j_auth(self) -> tuple[str, str]:
        return self.neo4j_user, self.neo4j_password


settings = Settings()
