from fastapi import APIRouter, Depends, HTTPException, Query, Response
from typing import Optional
from app.database import get_db_connection
from app.routes.auth import get_current_user

router = APIRouter(prefix="/api/transactions", tags=["Transactions"])

@router.get("/")
async def get_user_transactions(current_user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, recipient, amount, category, created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC",
        (current_user["id"],)
    )
    txs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"user_id": current_user["id"], "transactions": txs}

@router.get("/echo")
async def echo_message(message: str = Query("Welcome to DevSecOps Bank")):
    """
    Demo endpoint for testing DAST reflected XSS scanners and proper header protection.
    """
    html_content = f"""
    <div class="alert-box">
        <h3>Echo Message Result:</h3>
        <p>{message}</p>
    </div>
    """
    return Response(content=html_content, media_type="text/html")
