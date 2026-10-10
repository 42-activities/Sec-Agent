import pytest

from sec_agent.config import settings


@pytest.fixture(autouse=True)
def isolated_rules(tmp_path, monkeypatch):
    """Every test gets factory-default rules in a private file, no proxy, no admin token."""
    monkeypatch.setattr(settings, "rules_file", str(tmp_path / "rules.json"))
    monkeypatch.setattr(settings, "proxy_url", "")
    monkeypatch.setattr(settings, "rules_admin_token", "")
