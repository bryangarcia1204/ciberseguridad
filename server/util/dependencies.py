# dependencies.py
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Optional
import re

from database import get_db, User, UserRole
from auth import verify_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login", auto_error=False)

async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    print("Cargando el usuario activo")
    if not token and request:
        cookie_token = request.cookies.get("access_token")
        if cookie_token:
            payload = verify_token(cookie_token)
        else:
            return None
    elif token and not request:
        payload = verify_token(token, expected_type="access")
    else:
        return None
    if not payload:
        return None
    username = payload.get("sub")
    if not username:
        return None
    user = db.query(User).filter(User.username == username).first()
    return user

async def get_current_active_user(
    current_user: Optional[User] = Depends(get_current_user)
) -> User:
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    # Aquí podrías verificar si la cuenta está bloqueada, etc.
    return current_user

def require_role(required_role: UserRole):
    def role_checker(current_user: User = Depends(get_current_active_user)):
        # Comparar el rol del usuario con el requerido (los roles tienen un orden: admin > operator > viewer)
        role_hierarchy = {
            UserRole.ADMIN: 3,
            UserRole.OPERATOR: 2,
            UserRole.VIEWER: 1
        }
        if role_hierarchy.get(current_user.role, 0) < role_hierarchy[required_role]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return role_checker