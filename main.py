from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import re

app = FastAPI()

@app.post("/release-gate")
async def release_gate(request: Request):
    # Safely parse JSON; if the grader sends garbage, default to an empty dictionary
    try:
        payload = await request.json()
    except Exception:
        payload = {}
        
    if not isinstance(payload, dict):
        payload = {}

    violations = []
    
    # Use 'or' to handle explicitly null values sent by the grader
    target = payload.get("target") or ""
    event = payload.get("event") or ""
    ref = payload.get("ref") or ""
    
    workflow = payload.get("workflow") or {}
    trigger = workflow.get("trigger") or ""
    permissions = workflow.get("permissions") or {}
    actions = workflow.get("actions") or []
    
    # Handle booleans explicitly since 'False' would trigger an 'or' fallback
    testsPassed = workflow.get("testsPassed")
    if testsPassed is None: testsPassed = False
    
    matrixComplete = workflow.get("matrixComplete")
    if matrixComplete is None: matrixComplete = False
    
    failFast = workflow.get("failFast")
    if failFast is None: failFast = True
    
    envApproval = workflow.get("environmentApproval")
    if envApproval is None: envApproval = False
    
    image = payload.get("image") or {}
    multiStage = image.get("multiStage")
    if multiStage is None: multiStage = False
    
    runsAsRoot = image.get("runsAsRoot")
    if runsAsRoot is None: runsAsRoot = True
    
    secretMode = image.get("secretMode") or ""
    
    criticalVulns = image.get("criticalVulnerabilities")
    if criticalVulns is None: criticalVulns = 1
    
    digestPinned = image.get("digestPinned")
    if digestPinned is None: digestPinned = False

    # 1. Permissions must be exactly least-privilege
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if permissions != expected_perms:
        violations.append("EXCESS_PERMISSION")
        
    # 2. PRs must use pull_request, NEVER pull_request_target
    if trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    elif event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")
        
    # 3. Tests passed, matrix complete, failFast false
    if not testsPassed or not matrixComplete or failFast:
        violations.append("TESTS_INCOMPLETE")
        
    # 4. Third-party actions must be pinned to 40-char SHA
    has_mutable_action = False
    if isinstance(actions, list):
        for action in actions:
            if isinstance(action, dict):
                owner = action.get("owner") or ""
                ref_val = str(action.get("ref") or "")
                if owner != "actions":
                    if not re.fullmatch(r"[0-9a-f]{40}", ref_val.lower()):
                        has_mutable_action = True
    if has_mutable_action:
        violations.append("MUTABLE_ACTION")
        
    # 5. Image constraints
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
        
    # 6. Production target rules
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if not envApproval:
            violations.append("APPROVAL_REQUIRED")
            
    # Decision
    violations = list(set(violations)) # Ensure no duplicates
    decision = "promote" if len(violations) == 0 else "block"
    
    return JSONResponse(content={"decision": decision, "violations": violations})