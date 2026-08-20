from fastapi import FastAPI, Request
import re

app = FastAPI()

@app.post("/release-gate")
async def release_gate(request: Request):
    # Accept any JSON without strict Pydantic validation
    payload = await request.json()
    violations = []
    
    # Safely extract values using .get() to prevent missing-key errors
    target = payload.get("target", "")
    event = payload.get("event", "")
    ref = payload.get("ref", "")
    
    workflow = payload.get("workflow", {})
    trigger = workflow.get("trigger", "")
    permissions = workflow.get("permissions", {})
    testsPassed = workflow.get("testsPassed", False)
    matrixComplete = workflow.get("matrixComplete", False)
    failFast = workflow.get("failFast", True)
    actions = workflow.get("actions", [])
    envApproval = workflow.get("environmentApproval", False)
    
    image = payload.get("image", {})
    multiStage = image.get("multiStage", False)
    runsAsRoot = image.get("runsAsRoot", True)
    secretMode = image.get("secretMode", "")
    criticalVulns = image.get("criticalVulnerabilities", 1)
    digestPinned = image.get("digestPinned", False)

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
    for action in actions:
        owner = action.get("owner", "")
        ref_val = action.get("ref", "")
        if owner != "actions":
            if not re.fullmatch(r"[0-9a-f]{40}", ref_val):
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
    decision = "promote" if len(violations) == 0 else "block"
    return {"decision": decision, "violations": violations}