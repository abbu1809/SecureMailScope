"""
Rules API Router.
Provides public registry access to all deterministic cryptographic security rules.
"""
from typing import List, Optional
from fastapi import APIRouter, Query
from app.core.schemas import RuleDefinitionModel
from app.engine.rules_data import RULES_DATABASE

router = APIRouter(prefix="/api/rules", tags=["Rules Engine"])

@router.get("", response_model=List[RuleDefinitionModel])
async def list_rules(
    category: Optional[str] = Query(None, description="Filter rules by category"),
    severity: Optional[str] = Query(None, description="Filter rules by severity")
):
    """Lists all active deterministic cryptographic security rules."""
    rules = RULES_DATABASE
    if category:
        rules = [r for r in rules if category.lower() in r["category"].lower()]
    if severity:
        rules = [r for r in rules if severity.upper() == r["severity"].upper()]

    return [RuleDefinitionModel(**r) for r in rules]
