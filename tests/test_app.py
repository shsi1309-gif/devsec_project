from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db

client = TestClient(app)

def setup_module():
    init_db()

def test_health_endpoint():
    response = client.get("/healthz")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data

def test_root_index_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "DevSecOps Security Target App" in response.text

def test_search_users_secure():
    response = client.get("/api/users/search?q=alice&mode=secure")
    assert response.status_code == 200
    data = response.json()
    assert data["query"] == "alice"
    assert len(data["results"]) >= 1
    assert data["results"][0]["username"] == "alice"

def test_search_users_vulnerable_mode():
    response = client.get("/api/users/search?q=alice&mode=vulnerable")
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "vulnerable"
    assert len(data["results"]) >= 1

def test_auth_login_and_me():
    # Login as admin
    login_res = client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "admin123"}
    )
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    # Access protected /me route
    me_res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "admin"
    assert me_res.json()["role"] == "admin"
