from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config_loader import get_settings

Base = declarative_base()

class Database:
    """Handles database connections and sessions."""
    _engine = None
    _session_factory = None

    @classmethod
    def initialize(cls, database_url: str, echo: bool = False):
        """Initialize the async engine and sessionmaker."""
        if cls._engine is None:  # Ensure engine is created once
            cls._engine = create_async_engine(database_url, echo=echo, future=True)
            cls._session_factory = sessionmaker(
                bind=cls._engine, class_=AsyncSession, expire_on_commit=False, future=True
            )

    @classmethod
    def get_session_factory(cls):
        """Returns the session factory, ensuring it's initialized."""
        if cls._session_factory is None:
            raise ValueError("Database not initialized. Call `initialize()` first.")
        return cls._session_factory

# Initialize database with settings
settings = get_settings()
Database.initialize(settings.database_url, echo=settings.debug)

# Dependency to get async database session
async def get_async_session() -> AsyncSession:
    session_factory = Database.get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close()