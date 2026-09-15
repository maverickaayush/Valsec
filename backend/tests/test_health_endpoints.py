import asyncio
import json

from main import health, ready
import main


def test_health_is_process_liveness():
    assert health() == {"status": "ok"}


def test_ready_reports_dependencies(monkeypatch):
    async def inline(check): return check()
    monkeypatch.setattr(main.asyncio, "to_thread", inline)
    for name in ("_check_database", "_check_redis", "_check_ollama"):
        monkeypatch.setattr(main, name, lambda: None)
    assert asyncio.run(ready())["status"] == "ready"


def test_ready_degrades_and_production_hides_details(monkeypatch):
    async def inline(check): return check()
    monkeypatch.setattr(main.asyncio, "to_thread", inline)
    def failed(): raise RuntimeError("postgresql://user:secret@private-host/db")
    monkeypatch.setattr(main, "_check_database", failed)
    monkeypatch.setattr(main, "_check_redis", lambda: None)
    monkeypatch.setattr(main, "_check_ollama", lambda: None)
    monkeypatch.setattr(main, "is_production", lambda: True)
    response = asyncio.run(ready())
    body = json.loads(response.body)
    assert response.status_code == 503
    assert body["dependencies"]["database"]["error"] == "unavailable"
    assert "secret" not in response.body.decode()


def test_ollama_probe_uses_configured_auth_without_inference(monkeypatch):
    observed = {}

    class Response:
        def raise_for_status(self):
            observed["raised"] = True

    def get(url, **kwargs):
        observed.update(url=url, **kwargs)
        return Response()

    monkeypatch.setattr(main.settings, "OLLAMA_URL", "https://models.example.test/")
    monkeypatch.setattr(main.settings, "OLLAMA_AUTH_TOKEN", "probe-token")
    monkeypatch.setattr(main.requests, "get", get)
    main._check_ollama()
    assert observed == {
        "url": "https://models.example.test/api/tags",
        "headers": {"Authorization": "Bearer probe-token"},
        "timeout": 0.75,
        "raised": True,
    }
