import subprocess
import sys
import os

def main():
    print("Starting CIPHER Platform in separate terminal windows...")

    # Ensure we are in the project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(project_root, "backend")
    frontend_dir = os.path.join(project_root, "frontend")

    # Command to run the backend (FastAPI)
    # Using 'cmd.exe /k' keeps the window open even if the command crashes so you can read the error
    backend_cmd = f'cmd.exe /k "cd /d "{backend_dir}" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"'
    
    # Command to run the frontend (Vite)
    frontend_cmd = f'cmd.exe /k "cd /d "{frontend_dir}" && npm run dev"'

    # subprocess.CREATE_NEW_CONSOLE is a Windows-specific flag
    CREATE_NEW_CONSOLE = 0x00000010

    try:
        print("Launching Backend Terminal...")
        subprocess.Popen(backend_cmd, creationflags=CREATE_NEW_CONSOLE)

        print("Launching Frontend Terminal...")
        subprocess.Popen(frontend_cmd, creationflags=CREATE_NEW_CONSOLE)

        print("\nBoth services have been launched in their own terminal windows!")
        print("You can safely close this original window if you wish.")
    except Exception as e:
        print(f"Error launching services: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Ensure this runs only on Windows where CREATE_NEW_CONSOLE exists
    if os.name != 'nt':
        print("This script is specifically designed for Windows to open new terminal windows.")
        print("Please run the backend and frontend manually in your OS.")
        sys.exit(1)
        
    main()
