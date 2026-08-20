from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json
import re

app = FastAPI()

@app.post("/release-gate")
async def release_gate(request: Request):
    try:
        # Read the raw body to avoid FastAPI's strict JSON decoder crashes
        body = await request.body()
        payload = json.loads(body)
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}

    violations = []

    # --- BULLETPROOF DATA EXTRACTION HELPERS ---
    # These guarantee we never get a TypeError or AttributeError
    def get_dict(d, key):
        v = d.get(key)
        return v if isinstance(v, dict) else {}

    def get_list(d, key):
        v = d.get(key)
        return v if isinstance(v, list) else []

    def get_str(d, key):
        v = d.get(key)
        return str(v) if v is not None else ""

    def get_bool(d, key, default):
        v = d.get(key)
        return v if isinstance(v, bool) else default

    def get_int(d, key, default):
        try:
            return int(d.get(key))
        except (ValueError, TypeError):
            return default

    # --- SAFELY EXTRACT ALL VARIABLES ---
    target = get_str(payload, "target")
    event = get_str(payload, "event")
    ref = get_str(payload, "ref")

    workflow = get_dict(payload, "workflow")
    trigger = get_str(workflow, "trigger")
    permissions = get_dict(workflow, "permissions")
    testsPassed = get_bool(workflow, "testsPassed", False)
    matrixComplete = get_bool(workflow, "matrixComplete", False)
    failFast = get_bool(workflow, "failFast", True)
    actions = get_list(workflow, "actions")
    envApproval = get_bool(workflow, "environmentApproval", False)

    image = get_dict(payload, "image")
    multiStage = get_bool(image, "multiStage", False)
    runsAsRoot = get_bool(image, "runsAsRoot", True)
    secretMode = get_str(image, "secretMode")
    criticalVulns = get_int(image, "criticalVulnerabilities", 1)
    digestPinned = get_bool(image, "digestPinned", False)

    # --- APPLY RULES ---
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if permissions != expected_perms:
        violations.append("EXCESS_PERMISSION")
        
    if trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    elif event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")
        
    if not testsPassed or not matrixComplete or failFast:
        violations.append("TESTS_INCOMPLETE")
        
    has_mutable = False
    for action in actions:
        if isinstance(action, dict):
            owner = get_str(action, "owner")
            ref_val = get_str(action, "ref").lower()
            if owner != "actions":
                if not re.fullmatch(r"[0-9a-f]{40}", ref_val):
                    has_mutable = True
    if has_mutable:
        violations.append("MUTABLE_ACTION")
        
    if not multiStage:
        violations.append("SINGLE_STAGE_IMAGE")
    if runsAsRoot:
        violations.append("ROOT_RUNTIME")
    if secretMode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")
    if criticalVulns > 0:
        violations.append("CRITICAL_CVE")
    if not digestPinned:
        violations.append("UNPINNED_IMAGE")
        
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if not envApproval:
            violations.append("APPROVAL_REQUIRED")
            
    # Remove duplicates and decide
    violations = list(set(violations))
    decision = "promote" if not violations else "block"
    
    return JSONResponse(content={"decision": decision, "violations": violations})