import pytest
from network_monitor.storage.database import Database
from network_monitor.storage.migrations import apply_migrations
from network_monitor.storage.repository import NetworkRepository


@pytest.fixture
def in_memory_repo():
    db = Database(":memory:")
    apply_migrations(db)
    return NetworkRepository(db)
