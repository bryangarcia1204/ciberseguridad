# audit.py
from sqlalchemy.orm import Session
from database import AuditLog
from typing import Optional
from fastapi import Request

def log_action(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    agent_id: Optional[int] = None,
    resource: Optional[str] = None,
    details: Optional[dict] = None,
    request: Optional[Request] = None
):
    ip_address = request.client.host if request else None
    log = AuditLog(
        user_id=user_id,
        agent_id=agent_id,
        action=action,
        resource=resource,
        details=details,
        ip_address=ip_address
    )
    db.add(log)
    db.commit()