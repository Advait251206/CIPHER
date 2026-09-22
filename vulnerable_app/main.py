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
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CIPHER | Vulnerable Target</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {
                darkMode: 'class',
                theme: {
                    extend: {
                        colors: {
                            background: '#000000',
                            card: '#0a0a0a',
                            border: '#333333',
                            primary: '#d4af37',
                            primaryHover: '#b5952f'
                        }
                    }
                }
            }
        </script>
    </head>
    <body class="bg-background text-zinc-100 min-h-screen flex items-center justify-center p-6 antialiased">
        <div class="max-w-4xl w-full grid grid-cols-1 md:grid-cols-2 gap-8">
            <!-- Left Side: Info -->
            <div class="flex flex-col justify-center">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 text-red-400 text-sm font-medium w-fit mb-6 border border-red-500/20">
                    <span class="relative flex h-2 w-2">
                      <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                      <span class="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                    </span>
                    Live Target Environment
                </div>
                <h1 class="text-4xl font-bold tracking-tight mb-4">Vulnerable App</h1>
                <p class="text-zinc-400 leading-relaxed mb-6">
                    This application is intentionally vulnerable to <span class="text-zinc-200 font-semibold">SQL Injection (SQLi)</span>, <span class="text-zinc-200 font-semibold">Cross-Site Scripting (XSS)</span>, and <span class="text-zinc-200 font-semibold">Brute Force attacks</span>. 
                </p>
                <p class="text-zinc-500 text-sm">
                    Use this environment to safely trigger and analyze alerts in the CIPHER SOC Dashboard.
                </p>
            </div>

            <!-- Right Side: Forms -->
            <div class="flex flex-col">
                <!-- Toggle Tabs -->
                <div class="flex bg-zinc-900 rounded-lg p-1 border border-zinc-800 w-full mb-6 shadow-lg">
                    <button id="tab-login" type="button" onclick="showForm('login')" class="flex-1 py-2 text-sm font-medium rounded-md bg-zinc-800 text-white shadow-sm transition-all focus:outline-none">Sign In</button>
                    <button id="tab-signup" type="button" onclick="showForm('signup')" class="flex-1 py-2 text-sm font-medium rounded-md text-zinc-400 hover:text-white transition-all focus:outline-none">Create Account</button>
                </div>

                <!-- Login Card -->
                <div id="form-login" class="bg-card border border-border rounded-xl p-6 shadow-xl block">
                    <h2 class="text-xl font-semibold mb-1">Sign In</h2>
                    <p class="text-zinc-400 text-sm mb-5">Enter your credentials to access the dashboard.</p>
                    <form action="/login" method="post" class="space-y-4">
                        <div class="space-y-1.5">
                            <label class="text-sm font-medium text-zinc-300">Username</label>
                            <input type="text" name="username" class="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-colors">
                        </div>
                        <div class="space-y-1.5">
                            <label class="text-sm font-medium text-zinc-300">Password</label>
                            <input type="password" name="password" class="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-colors">
                        </div>
                        <button type="submit" class="w-full bg-primary hover:bg-primaryHover text-white font-medium py-2 rounded-md transition-colors text-sm mt-2">Sign In</button>
                    </form>
                </div>

                <!-- Signup Card -->
                <div id="form-signup" class="bg-card border border-border rounded-xl p-6 shadow-xl hidden">
                    <h2 class="text-xl font-semibold mb-1">Create Account</h2>
                    <p class="text-zinc-400 text-sm mb-5">Register a new user profile in the database.</p>
                    <form action="/signup" method="post" class="space-y-4">
                        <div class="grid grid-cols-2 gap-4">
                            <div class="space-y-1.5">
                                <label class="text-sm font-medium text-zinc-300">Username</label>
                                <input type="text" name="username" class="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-colors">
                            </div>
                            <div class="space-y-1.5">
                                <label class="text-sm font-medium text-zinc-300">Password</label>
                                <input type="password" name="password" class="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-colors">
                            </div>
                        </div>
                        <div class="space-y-1.5">
                            <label class="text-sm font-medium text-zinc-300">Full Name</label>
                            <input type="text" name="full_name" class="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-colors">
                        </div>
                        <div class="space-y-1.5">
                            <label class="text-sm font-medium text-zinc-300">Email Address</label>
                            <input type="text" name="email" class="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-colors">
                        </div>
                        <button type="submit" class="w-full bg-zinc-800 hover:bg-zinc-700 text-white font-medium py-2 rounded-md transition-colors text-sm border border-zinc-700 mt-2">Register</button>
                    </form>
                </div>
            </div>
        </div>
        
        <script>
            function showForm(type) {
                const loginForm = document.getElementById('form-login');
                const signupForm = document.getElementById('form-signup');
                const loginTab = document.getElementById('tab-login');
                const signupTab = document.getElementById('tab-signup');
                
                if (type === 'login') {
                    loginForm.classList.remove('hidden');
                    loginForm.classList.add('block');
                    signupForm.classList.remove('block');
                    signupForm.classList.add('hidden');
                    
                    loginTab.classList.add('bg-zinc-800', 'text-white', 'shadow-sm');
                    loginTab.classList.remove('text-zinc-400');
                    
                    signupTab.classList.remove('bg-zinc-800', 'text-white', 'shadow-sm');
                    signupTab.classList.add('text-zinc-400');
                } else {
                    signupForm.classList.remove('hidden');
                    signupForm.classList.add('block');
                    loginForm.classList.remove('block');
                    loginForm.classList.add('hidden');
                    
                    signupTab.classList.add('bg-zinc-800', 'text-white', 'shadow-sm');
                    signupTab.classList.remove('text-zinc-400');
                    
                    loginTab.classList.remove('bg-zinc-800', 'text-white', 'shadow-sm');
                    loginTab.classList.add('text-zinc-400');
                }
            }
        </script>
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
        return f"""
        <!DOCTYPE html><html lang="en" class="dark"><head><script src="https://cdn.tailwindcss.com"></script><script>tailwind.config={{darkMode:'class',theme:{{extend:{{colors:{{background:'#000000',card:'#0a0a0a',border:'#333333',primary:'#d4af37',primaryHover:'#b5952f'}}}}}}}}</script></head>
        <body class="bg-background text-zinc-100 min-h-screen flex items-center justify-center p-6">
            <div class="max-w-2xl w-full bg-card border border-red-500/30 rounded-xl p-6 shadow-xl">
                <div class="flex items-center gap-3 mb-4">
                    <div class="p-2 bg-red-500/10 text-red-500 rounded-lg"><svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg></div>
                    <h3 class="text-xl font-bold text-red-500">Database Error (SQLi)</h3>
                </div>
                <div class="bg-zinc-950 border border-zinc-800 rounded-lg p-4 mb-6 overflow-x-auto font-mono text-sm">
                    <p class="text-red-400 mb-2">{e}</p>
                    <p class="text-zinc-500 mt-4">Executed Query:</p>
                    <p class="text-zinc-300 break-all">{query}</p>
                </div>
                <a href="/" class="inline-flex items-center text-blue-500 hover:text-blue-400 font-medium text-sm transition-colors">&larr; Back to Safety</a>
            </div>
        </body></html>
        """
    finally:
        conn.close()
        
    return f"""
    <!DOCTYPE html><html lang="en" class="dark"><head><script src="https://cdn.tailwindcss.com"></script><script>tailwind.config={{darkMode:'class',theme:{{extend:{{colors:{{background:'#000000',card:'#0a0a0a',border:'#333333',primary:'#d4af37',primaryHover:'#b5952f'}}}}}}}}</script></head>
    <body class="bg-background text-zinc-100 min-h-screen flex items-center justify-center p-6">
        <div class="max-w-md w-full bg-card border border-green-500/30 rounded-xl p-8 shadow-xl text-center">
            <div class="mx-auto w-16 h-16 bg-green-500/10 text-green-500 rounded-full flex items-center justify-center mb-6">
                <svg class="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
            </div>
            <h3 class="text-2xl font-bold mb-2">Registration Successful</h3>
            <p class="text-zinc-400 mb-8">Your account has been created in the database.</p>
            <a href="/" class="block w-full bg-primary hover:bg-primaryHover text-white font-medium py-2.5 rounded-lg transition-colors text-sm">Return to Login</a>
        </div>
    </body></html>
    """

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
        return f"""
        <!DOCTYPE html><html lang="en" class="dark"><head><script src="https://cdn.tailwindcss.com"></script><script>tailwind.config={{darkMode:'class',theme:{{extend:{{colors:{{background:'#000000',card:'#0a0a0a',border:'#333333',primary:'#d4af37',primaryHover:'#b5952f'}}}}}}}}</script></head>
        <body class="bg-background text-zinc-100 min-h-screen flex items-center justify-center p-6">
            <div class="max-w-2xl w-full bg-card border border-red-500/30 rounded-xl p-6 shadow-xl">
                <div class="flex items-center gap-3 mb-4">
                    <div class="p-2 bg-red-500/10 text-red-500 rounded-lg"><svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg></div>
                    <h3 class="text-xl font-bold text-red-500">Database Error (SQLi)</h3>
                </div>
                <div class="bg-zinc-950 border border-zinc-800 rounded-lg p-4 mb-6 overflow-x-auto font-mono text-sm">
                    <p class="text-red-400 mb-2">{e}</p>
                    <p class="text-zinc-500 mt-4">Executed Query:</p>
                    <p class="text-zinc-300 break-all">{query}</p>
                </div>
                <a href="/" class="inline-flex items-center text-blue-500 hover:text-blue-400 font-medium text-sm transition-colors">&larr; Back to Safety</a>
            </div>
        </body></html>
        """
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
        <!DOCTYPE html><html lang="en" class="dark"><head><script src="https://cdn.tailwindcss.com"></script><script>tailwind.config={{darkMode:'class',theme:{{extend:{{colors:{{background:'#000000',card:'#0a0a0a',border:'#333333',primary:'#d4af37',primaryHover:'#b5952f'}}}}}}}}</script></head>
        <body class="bg-background text-zinc-100 min-h-screen p-8">
            <div class="max-w-4xl mx-auto">
                <header class="flex items-center justify-between mb-8 pb-6 border-b border-border">
                    <div class="flex items-center gap-3">
                        <div class="p-1.5 bg-primary/10 text-primary rounded-lg"><svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></div>
                        <h2 class="text-2xl font-bold tracking-tight">User Dashboard</h2>
                    </div>
                    <a href="/" class="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-md text-sm font-medium transition-colors">Logout</a>
                </header>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="md:col-span-1">
                        <div class="bg-card border border-border rounded-xl p-6 shadow-lg">
                            <div class="w-20 h-20 bg-primary/20 text-primary rounded-full flex items-center justify-center text-3xl font-bold mb-4 mx-auto">
                                {(full_name[0].upper() if len(full_name) > 0 else '?') if full_name else '?'}
                            </div>
                            <div class="text-center">
                                <h3 class="text-lg font-semibold text-zinc-100 mb-1">{full_name}</h3>
                                <p class="text-zinc-400 text-sm break-all">{email}</p>
                            </div>
                        </div>
                    </div>
                    <div class="md:col-span-2">
                        <div class="bg-card border border-border rounded-xl p-6 shadow-lg h-full">
                            <h3 class="text-lg font-medium mb-4 text-zinc-200">Recent Activity</h3>
                            <div class="space-y-4">
                                <div class="flex gap-4 items-start">
                                    <div class="w-2 h-2 rounded-full bg-green-500 mt-2"></div>
                                    <div>
                                        <p class="text-sm font-medium text-zinc-300">Successful Login</p>
                                        <p class="text-xs text-zinc-500">Just now</p>
                                    </div>
                                </div>
                                <div class="flex gap-4 items-start opacity-50">
                                    <div class="w-2 h-2 rounded-full bg-blue-500 mt-2"></div>
                                    <div>
                                        <p class="text-sm font-medium text-zinc-300">Account Created</p>
                                        <p class="text-xs text-zinc-500">System Log</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body></html>
        """
        return html
    else:
        # VULNERABILITY 5: No Rate Limiting (Allows Brute Force)
        return f"""
        <!DOCTYPE html><html lang="en" class="dark"><head><script src="https://cdn.tailwindcss.com"></script><script>tailwind.config={{darkMode:'class',theme:{{extend:{{colors:{{background:'#000000',card:'#0a0a0a',border:'#333333',primary:'#d4af37',primaryHover:'#b5952f'}}}}}}}}</script></head>
        <body class="bg-background text-zinc-100 min-h-screen flex items-center justify-center p-6">
            <div class="max-w-md w-full bg-card border border-red-500/30 rounded-xl p-8 shadow-xl text-center">
                <div class="mx-auto w-16 h-16 bg-red-500/10 text-red-500 rounded-full flex items-center justify-center mb-6">
                    <svg class="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                </div>
                <h3 class="text-2xl font-bold mb-2">Authentication Failed</h3>
                <p class="text-zinc-400 mb-8">Invalid username or password.</p>
                <a href="/" class="block w-full bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-white font-medium py-2.5 rounded-lg transition-colors text-sm">Try Again</a>
            </div>
        </body></html>
        """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
