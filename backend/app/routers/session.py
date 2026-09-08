from fastapi import APIRouter, Depends
from ..deps import get_current_user
from ..models import User

router = APIRouter()

@router.get("/me")
async def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "is_active": user.is_active}
