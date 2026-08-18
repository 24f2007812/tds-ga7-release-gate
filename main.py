from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List, Dict
import re

app = FastAPI()

class ActionDef(BaseModel):
    owner: str
    name: str
    ref: str

class WorkflowDef(BaseModel):
    trigger: str
    permissions: Dict[str, str]
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[ActionDef]
    environmentApproval: Optional[bool] = None

class ImageDef(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool

class Payload(BaseModel):
    target: str
    event: str
    ref: str
    workflow: WorkflowDef
    image: ImageDef

@app.post("/release-gate")
def release_gate(payload: Payload):
    violations = []
    
    # 1. Permissions must be exactly least-privilege
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if payload.workflow.permissions != expected_perms:
        violations.append("EXCESS_PERMISSION")
        
    # 2. PRs must use pull_request, NEVER pull_request_target
    if payload.workflow.trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    elif payload.event == "pull_request" and payload.workflow.trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")
        
    # 3. Tests passed, matrix complete, failFast false
    if not payload.workflow.testsPassed or not payload.workflow.matrixComplete or payload.workflow.failFast:
        violations.append("TESTS_INCOMPLETE")
        
    # 4. Third-party actions must be pinned to 40-char SHA
    has_mutable_action = False
    for action in payload.workflow.actions:
        if action.owner != "actions":
            # Check if it's exactly a 40 character lowercase hex string
            if not re.fullmatch(r"[0-9a-f]{40}", action.ref):
                has_mutable_action = True
    if has_mutable_action:
        violations.append("MUTABLE_ACTION")
        
    # 5. Image constraints
    if not payload.image.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")
        
    if payload.image.runsAsRoot:
        violations.append("ROOT_RUNTIME")
        
    if payload.image.secretMode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")
        
    if payload.image.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")
        
    if not payload.image.digestPinned:
        violations.append("UNPINNED_IMAGE")
        
    # 6. Production target rules
    if payload.target == "production":
        if payload.event != "push" or payload.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if not payload.workflow.environmentApproval:
            violations.append("APPROVAL_REQUIRED")
            
    # Decision
    decision = "promote" if len(violations) == 0 else "block"
    
    # Violations order does not matter
    return {"decision": decision, "violations": violations}