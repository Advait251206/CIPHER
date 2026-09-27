"""
CIPHER Users API Router
Manages the vulnerable app's users database (for demonstration purposes).
"""

import os
import sqlite3
from typing import List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

router = APIRouter(prefix="/vulnerable-users", tags=["Vulnerable Users"])

def get_db_connection():
    # Path to vulnerable_app/users.db relative to the backend
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    db_path = os.path.join(base_dir, "vulnerable_app", "users.db")
    
    if not os.path.exists(db_path):
        raise HTTPException(status_code=404, detail="Vulnerable app database not found.")
        
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

class User(BaseModel):
    id: int
    username: str
    password: str
    full_name: str
    email: str

class PasswordUpdate(BaseModel):
    new_password: str

@router.get("/", response_model=List[User])
def get_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        conn.close()
        
        users = []
        for row in rows:
            users.append({
                "id": row["id"],
                "username": row["username"],
                "password": row["password"],
                "full_name": row["full_name"],
                "email": row["email"]
            })
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{user_id}")
def delete_user(user_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        if cursor.rowcount == 0:
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")
        conn.commit()
        conn.close()
        return {"status": "success", "message": "User deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{user_id}/password")
def update_password(user_id: int, payload: PasswordUpdate):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (payload.new_password, user_id))
        if cursor.rowcount == 0:
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Password updated"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
