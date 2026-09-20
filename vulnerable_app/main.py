import sqlite3
import uvicorn
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

app = FastAPI()

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            full_name TEXT,
            email TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    html = """
    <html>
    <head><title>Vulnerable App</title></head>
    <body style="font-family: sans-serif; padding: 40px; max-width: 600px; margin: 0 auto;">
        <h1>Vulnerable Target App</h1>
        <p>This application is intentionally vulnerable to SQL Injection (SQLi), Cross-Site Scripting (XSS), and Brute Force attacks. Use for IDPS testing only.</p>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
            <h2>Login</h2>
            <form action="/login" method="post">
                <div>
                    <label>Username:</label><br>
                    <input type="text" name="username" style="width: 100%; padding: 8px; margin: 5px 0;">
                </div>
                <div>
                    <label>Password:</label><br>
                    <input type="password" name="password" style="width: 100%; padding: 8px; margin: 5px 0;">
                </div>
                <input type="submit" value="Login" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">
            </form>
        </div>

        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
            <h2>Sign Up</h2>
            <form action="/signup" method="post">
                <div>
                    <label>Username:</label><br>
                    <input type="text" name="username" style="width: 100%; padding: 8px; margin: 5px 0;">
                </div>
                <div>
                    <label>Password:</label><br>
                    <input type="password" name="password" style="width: 100%; padding: 8px; margin: 5px 0;">
                </div>
                <div>
                    <label>Full Name:</label><br>
                    <input type="text" name="full_name" style="width: 100%; padding: 8px; margin: 5px 0;">
                </div>
                <div>
                    <label>Email:</label><br>
                    <input type="text" name="email" style="width: 100%; padding: 8px; margin: 5px 0;">
                </div>
                <input type="submit" value="Sign Up" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer;">
            </form>
        </div>
    </body>
    </html>
    """
    return html

@app.post("/signup", response_class=HTMLResponse)
def signup(username: str = Form(...), password: str = Form(...), full_name: str = Form(...), email: str = Form(...)):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # VULNERABILITY 1: SQL Injection (Raw string formatting instead of parameterized queries)
    # Allows bypassing authentication or dumping database via UNION SELECT
    query = f"INSERT INTO users (username, password, full_name, email) VALUES ('{username}', '{password}', '{full_name}', '{email}')"
    
    try:
        # Using executescript allows multiple statements to be executed via SQLi
        c.executescript(query)
        conn.commit()
    except Exception as e:
        # VULNERABILITY 2: Error-based SQLi (Leaking database structure)
        return f"<h3>Database Error</h3><p style='color:red;'>{e}</p><p><strong>Query:</strong> {query}</p>"
    finally:
        conn.close()
        
    return "<h3>Signup successful!</h3><a href='/'>Go to login</a>"

@app.post("/login", response_class=HTMLResponse)
def login(username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # VULNERABILITY 3: SQL Injection in Login
    # Payload example for username: ' OR '1'='1' --
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    try:
        c.execute(query)
        user = c.fetchone()
    except Exception as e:
        return f"<h3>Database Error</h3><p style='color:red;'>{e}</p><p><strong>Query:</strong> {query}</p>"
    finally:
        conn.close()
        
    if user:
        # user tuple: (id, username, password, full_name, email)
        full_name = user[3]
        email = user[4]
        
        # VULNERABILITY 4: Stored Cross-Site Scripting (XSS)
        # Rendering user input directly into HTML without escaping.
        # If full_name was set to `<script>alert('XSS')</script>` during signup, it executes here.
        html = f"""
        <html>
        <head><title>Dashboard</title></head>
        <body style="font-family: sans-serif; padding: 40px; max-width: 600px; margin: 0 auto;">
            <h2 style="color: green;">Login successful</h2>
            <div style="background: #e9ecef; padding: 20px; border-radius: 8px;">
                <h3>User Dashboard</h3>
                <p><strong>Name:</strong> {full_name}</p>
                <p><strong>Email:</strong> {email}</p>
                <br>
                <a href="/">Logout</a>
            </div>
        </body>
        </html>
        """
        return html
    else:
        # VULNERABILITY 5: No Rate Limiting (Allows Brute Force)
        return "<h3>Invalid username or password.</h3><a href='/'>Try again</a>"

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
