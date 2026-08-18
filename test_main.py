from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_valid_payload():
    payload = {
      "target": "preview",
      "event": "pull_request",
      "ref": "refs/heads/feature",
      "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents":"read", "packages":"write", "id-token":"none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [{"owner":"actions", "name":"checkout", "ref":"v4"}]
      },
      "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True
      }
    }
    response = client.post("/release-gate", json=payload)
    assert response.status_code == 200
    assert response.json() == {"decision": "promote", "violations": []}