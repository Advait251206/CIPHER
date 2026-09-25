"""
CIPHER Extension API Router
Provides endpoints to manage, download, and auto-launch the CIPHER Browser Guard Chromium extension.
"""

import os
import io
import zipfile
import shutil
import subprocess
from urllib.parse import urlparse
import platform
import logging
from pathlib import Path
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("cipher.extension")

router = APIRouter(prefix="/extension", tags=["Browser Extension"])

# Base directory for the extension
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
EXTENSION_DIR = PROJECT_ROOT / "cipher-browser-extension"


class ExtensionStatusResponse(BaseModel):
    available: bool
    path: str
    manifest_name: str
    version: str
    browser_detected: bool


class LaunchBrowserRequest(BaseModel):
    target_url: str = "http://localhost:5173"


@router.get("/status", response_model=ExtensionStatusResponse)
def get_extension_status():
    """Returns local extension availability and directory metadata."""
    manifest_path = EXTENSION_DIR / "manifest.json"
    is_avail = manifest_path.exists()

    name = "CIPHER Browser Guard"
    version = "1.0.0"
    if is_avail:
        try:
            import json
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                name = data.get("name", name)
                version = data.get("version", version)
        except Exception:
            pass

    # Check if Chrome / Edge is on system
    has_browser = False
    if platform.system() == "Windows":
        # Check typical chrome / edge paths or where command
        for browser_cmd in ["chrome", "msedge", "brave"]:
            if shutil.which(browser_cmd):
                has_browser = True
                break
        if not has_browser:
            # Check common Program Files locations
            common_paths = [
                Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")) / "Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
            ]
            has_browser = any(p.exists() for p in common_paths)
    else:
        has_browser = bool(shutil.which("google-chrome") or shutil.which("chromium"))

    return ExtensionStatusResponse(
        available=is_avail,
        path=str(EXTENSION_DIR),
        manifest_name=name,
        version=version,
        browser_detected=has_browser
    )


@router.get("/download")
def download_extension_zip():
    """Packages the extension folder on-the-fly and downloads it as a .zip file."""
    if not EXTENSION_DIR.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Extension directory not found on host."
        )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(EXTENSION_DIR):
            for file in files:
                file_path = Path(root) / file
                archive_name = file_path.relative_to(EXTENSION_DIR)
                zip_file.write(file_path, str(archive_name))

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="cipher-browser-guard.zip"'
        }
    )


def _validated_launch_url(url: str) -> str:
    """Accept only absolute http(s) URLs for the browser's command line.

    Anything else is rejected, most importantly strings starting with "-",
    which Chrome would parse as command-line flags.
    """
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc or url.strip().startswith("-"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_url must be an absolute http(s) URL.",
        )
    return url.strip()


@router.post("/launch")
def launch_browser_with_extension(req: LaunchBrowserRequest = LaunchBrowserRequest()):
    """
    Launches Chrome with the CIPHER extension pre-loaded via CLI flags.
    Allows zero-manual-step installation and instant testing.
    """
    if not EXTENSION_DIR.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Extension directory not found."
        )

    ext_abs_path = str(EXTENSION_DIR.resolve())
    target_url = _validated_launch_url(req.target_url)

    try:
        import tempfile
        temp_profile = os.path.join(tempfile.gettempdir(), 'cipher_chrome_profile')

        browser_bin = None
        if platform.system() == "Windows":
            for cmd in ["chrome", "msedge", "brave"]:
                if shutil.which(cmd):
                    browser_bin = shutil.which(cmd)
                    break
            if not browser_bin:
                common_paths = [
                    Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")) / "Google/Chrome/Application/chrome.exe",
                    Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
                    Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
                    Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
                ]
                found = next((p for p in common_paths if p.exists()), None)
                if found:
                    browser_bin = str(found)
        else:
            browser_bin = shutil.which("google-chrome") or shutil.which("chromium")

        if browser_bin:
            subprocess.Popen([
                browser_bin,
                f"--user-data-dir={temp_profile}",
                "--no-first-run",
                f"--load-extension={ext_abs_path}",
                target_url
            ])
            return {
                "success": True,
                "message": "Browser launched with CIPHER extension pre-loaded.",
                "extension_path": ext_abs_path
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Chromium browser executable not found on host."
            )
    except Exception as e:
        logger.error(f"Failed to launch browser with extension: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to launch browser: {str(e)}"
        )
