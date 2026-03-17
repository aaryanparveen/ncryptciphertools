import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')

SECRET_KEY = os.environ.get('SECRET_KEY', 'ncrypt-secret-key-change-in-production')
NVIDIA_API_KEY = os.environ.get('NVIDIA_API_KEY', '')
NVIDIA_MODEL = os.environ.get('NVIDIA_MODEL', 'qwen/qwen3-235b-a22b')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
