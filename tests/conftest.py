import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """A real AWS/metadata call during tests is always a bug."""

    def blocked(*args, **kwargs):
        raise AssertionError("Tests must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
