from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from app.database import get_db_connection, search_users_vulnerable, search_users_secure
from app.routes.auth import get_current_user

router = APIRouter(prefix="/api/users", tags=["Users"])

@router.get("/")
async def list_users(current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, balance FROM users")
    users = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"status": "success", "count": len(users), "data": users}

@router.get("/search")
async def search_users(
    q: str = Query(..., description="Search query string"),
    mode: str = Query("secure", description="Search mode: 'secure' or 'vulnerable' for testing")
):
    """
    Search endpoint supporting both secure parameterized queries and
    a controlled vulnerable implementation for demonstrating SAST/DAST detection.
    """
    if mode == "vulnerable":
        results = search_users_vulnerable(q)
    else:
        results = search_users_secure(q)
    return {"query": q, "mode": mode, "results": results}

@router.get("/{user_id}")
async def get_user_profile(user_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, balance FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)
