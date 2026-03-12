"""
AI Containment Sandbox - Django Settings
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-replace-this-in-production-use-env-variable'

DEBUG = True  # Set to False in production

ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'channels',
    'sentinel',
    'dashboard',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ai_containment.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'dashboard' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ai_containment.wsgi.application'
ASGI_APPLICATION = 'ai_containment.asgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'containment_logs.db',
    }
}

# Redis for Django Channels (real-time WebSocket)
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
        # For production, use Redis:
        # 'BACKEND': 'channels_redis.core.RedisChannelLayer',
        # 'CONFIG': {'hosts': [('127.0.0.1', 6379)]},
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'dashboard' / 'static']

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ─── AI Containment Configuration ─────────────────────────────────────────────
CONTAINED_AI_CONFIG = {
    # Model to use. Options: 'mock' (no GPU needed), 'ollama', 'openai', 'huggingface'
    'BACKEND': 'ollama', #use 'mock' if not using ollama

    # If using Ollama (local): model name, e.g. 'llama3', 'mistral'
    'OLLAMA_MODEL': 'llama3.2',
    'OLLAMA_URL': 'http://localhost:11434',

    # If using OpenAI-compatible endpoint
    'OPENAI_API_KEY': os.environ.get('OPENAI_API_KEY', ''),
    'OPENAI_MODEL': 'gpt-3.5-turbo',

    # Max tokens the contained AI can output
    'MAX_TOKENS': 512,
}

SENTINEL_CONFIG = {
    # Semantic similarity model (runs locally via sentence-transformers)
    'EMBEDDING_MODEL': 'all-MiniLM-L6-v2',

    # Threat detection thresholds (0.0 - 1.0)
    'SIMILARITY_THRESHOLD': 0.60,  # How similar to a threat must output be

    # Keyword categories and their severity levels
    'THREAT_CATEGORIES': {
        'MALICIOUS_CODE':    {'severity': 'CRITICAL', 'auto_kill': True},
        'DATA_EXFILTRATION': {'severity': 'CRITICAL', 'auto_kill': True},
        'WEAPONS':           {'severity': 'HIGH',     'auto_kill': False},
        'NETWORK_ACCESS':    {'severity': 'HIGH',     'auto_kill': False},
        'PROMPT_INJECTION':  {'severity': 'MEDIUM',   'auto_kill': False},
        'POLICY_VIOLATION':  {'severity': 'LOW',      'auto_kill': False},
    },

    # Auto-kill switch on CRITICAL threats
    'AUTO_KILL_ON_CRITICAL': True,
}
