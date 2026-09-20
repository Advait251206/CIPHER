from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict
from app.network.live_sensor.waf_engine import waf_engine

router = APIRouter(tags=["WAF"])

class WAFConfigRequest(BaseModel):
    feature: str
    mode: str  # "off", "detect", "enforce"

@router.get("/waf/config")
def get_waf_config() -> Dict[str, str]:
    """Retrieve the current configuration of the WAF engine."""
    return waf_engine.config

@router.post("/waf/config")
def update_waf_config(req: WAFConfigRequest):
    """Update a specific WAF protection mode."""
    if req.feature not in waf_engine.config:
        raise HTTPException(status_code=400, detail="Unknown WAF feature")
    if req.mode not in ["off", "detect", "enforce"]:
        raise HTTPException(status_code=400, detail="Invalid mode")
        
    waf_engine.update_config(req.feature, req.mode)
    return {"status": "success", "config": waf_engine.config}
