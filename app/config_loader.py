from pathlib import Path
from pydantic import Field, AnyUrl, ConfigDict
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    max_login_attempts: int = Field(default=3)
    server_base_url: AnyUrl = Field(default="http://localhost")
    server_download_folder: str = Field(default="downloads")
    
    secret_key: str = Field(default="secret-key")
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)
    admin_user: str = Field(default="admin")
    admin_password: str = Field(default="secret")
    debug: bool = Field(default=False)
    
    jwt_secret_key: str = Field(default="a_very_secret_key")
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_minutes: int = Field(default=1440)
    
    database_url: str = Field(default="postgresql+asyncpg://user:password@postgres/myappdb")
    
    postgres_user: str = Field(default="user")
    postgres_password: str = Field(default="password")
    postgres_server: str = Field(default="localhost")
    postgres_port: str = Field(default="5432")
    postgres_db: str = Field(default="myappdb")
    
    discord_bot_token: str = Field(default="NONE")
    discord_channel_id: int = Field(default=1234567890)
    
    openai_api_key: str = Field(default="NONE")
    send_real_mail: bool = Field(default=False)
    
    smtp_server: str = Field(default="smtp.mailtrap.io")
    smtp_port: int = Field(default=2525)
    smtp_username: str = Field(default="your-mailtrap-username")
    smtp_password: str = Field(default="your-mailtrap-password")

# Singleton instance
settings = Settings()
