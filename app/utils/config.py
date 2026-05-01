import os
from dotenv import load_dotenv

load_dotenv()

# Help weasyprint find Homebrew-installed system libraries on macOS
if os.path.exists("/opt/homebrew/lib"):
    _current = os.environ.get("DYLD_LIBRARY_PATH", "")
    os.environ["DYLD_LIBRARY_PATH"] = f"/opt/homebrew/lib:{_current}" if _current else "/opt/homebrew/lib"

class Config:
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    VT_API_KEY = os.getenv("VT_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    MB_API_KEY = os.getenv("MB_API_KEY", "")

    VT_CALLS_PER_MINUTE = 4       # free tier hard limit
    ABUSEIPDB_DAILY_LIMIT = 1000  # free tier hard limit

    OFFLINE_MODE = os.getenv("OFFLINE_MODE", "false").lower() == "true"

config = Config()
