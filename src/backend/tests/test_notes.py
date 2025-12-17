from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_root_ok():
    """El backend responde correctamente"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_get_notes_initially_empty():
    """Al inicio no hay notas"""
    response = client.get("/notes")
    assert response.status_code == 200
    assert response.json() == []


def test_add_note():
    """Se puede agregar una nota"""
    payload = {
        "title": "Test note",
        "content": "Hello world"
    }

    response = client.post("/notes", json=payload)
    assert response.status_code == 200

    response = client.get("/notes")
    assert len(response.json()) == 1
