
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-&3ec69-q6s4@*z@7v()&0md5si@w7%rxf8yku5)jlc*$a&p0i1'

DEBUG = True

ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
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

ROOT_URLCONF = 'deploy_platform.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'core.context_processors.github_connected',
            ],
        },
    },
]

WSGI_APPLICATION = 'deploy_platform.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'easydeploy',
        'USER': 'postgres',
        'PASSWORD': 'Minimax999157',
        'HOST': 'database-1.c728eaaievd3.us-east-1.rds.amazonaws.com',
        'PORT': '5432',
        'OPTIONS': {
            'sslmode': os.environ.get('DB_SSLMODE', 'prefer'),
        },
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

STATIC_URL = 'static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/'

GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID', 'Ov23liDBqBoJA5motUgG')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', '100d4a956460db2e54ac8bc0980dcdfe40eafb18')
GITHUB_REDIRECT_URI = os.environ.get('GITHUB_REDIRECT_URI', 'http://100.25.10.212/github/callback/')

LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/'

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

PUBLIC_BASE_URL = os.environ.get('PUBLIC_BASE_URL', '')

REMOTE_DEPLOY_HOSTS = os.environ.get('REMOTE_DEPLOY_HOSTS', '')
if REMOTE_DEPLOY_HOSTS:
    REMOTE_DEPLOY_HOSTS = [h.strip() for h in REMOTE_DEPLOY_HOSTS.split(',') if h.strip()]
else:
    REMOTE_DEPLOY_HOSTS = []
REMOTE_DEPLOY_SSH_USER = os.environ.get('REMOTE_DEPLOY_SSH_USER', '')
REMOTE_DEPLOY_SSH_KEY_PATH = os.environ.get('REMOTE_DEPLOY_SSH_KEY_PATH', '')
LOCAL_HOST_IP = os.environ.get('LOCAL_HOST_IP', '')
