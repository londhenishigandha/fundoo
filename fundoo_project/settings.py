"""
Django settings for fundoo_project project.

Generated by 'django-admin startproject' using Django 2.2.1.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""
from __future__ import absolute_import
import os
from dotenv import load_dotenv, find_dotenv


# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.

from pathlib import *
load_dotenv(find_dotenv())
env_path = Path('.')/'.env'

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
MEDIA_DIR = os.path.join(BASE_DIR, 'media')

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'c5fs*wck!$!lj)epgvwhqg5m6gizgi=#@2_mba#7vr!tr6+64q'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'social_django',  # For Social media
    'rest_framework',
    'rest_framework.authtoken',
    'notifications',
    'webpush',
    'fundoonote',
    'django_elasticsearch_dsl',
    'django_elasticsearch_dsl_drf',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',  # social media auth
]

ROOT_URLCONF = 'fundoo_project.urls'


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [TEMPLATE_DIR, ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'social_django.context_processors.backends',  # <-- for social media
                'social_django.context_processors.login_redirect', # <-- for social media
            ]
        },
    },
]


WSGI_APPLICATION = 'fundoo_project.wsgi.application'

ELASTICSEARCH_DSL={
    'default': {
        'hosts': 'localhost:9200'
    },
}


DATABASES = {
    'default': {
        'ENGINE': os.getenv("DB_ENGINE"),
        'NAME': os.getenv("DB_NAME"),
        'USER': os.getenv("DB_USER"),
        'PASSWORD': os.getenv("DB_PASSWORD"),
        'HOST': os.getenv("DB_HOST"),
        'PORT': '5432',
}
}


# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

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

WEBPUSH_SETTINGS = {
   "VAPID_PUBLIC_KEY": "BDp1yxiN_Q-nRY2tyjotejESsp2V8Vop-BG4INxinpYI8i2_SZL7eGpBOXBMcD6L0VUZsqDZn9YrR55reh90IG8",
   "VAPID_PRIVATE_KEY": "JnuCdR5G6qofJIxaCNOfg1IM-2C4Ikeq8rYmZ5UPjuI",
   "VAPID_ADMIN_EMAIL": "londhenishigandha123@gmail.com"
}

# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
            'rest_framework.authentication.TokenAuthentication',
    )
}
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/static/'
STATICFILES_DIRS = [STATIC_DIR]
MEDIA_ROOT = MEDIA_DIR

# Email
# EMAIL_BACKEND = "django.core.mail.backends.filebased.EmailBackend"
# EMAIL_FILE_PATH = os.path.join(BASE_DIR, "sent_emails")


# SMTP
EMAIL_USE_TLS = True
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_PORT = os.getenv("EMAIL_PORT")

# redis chache

CACHES = {
    'default': {
        'BACKEND': 'redis_cache.RedisCache',
        'LOCATION': 'localhost:6379',
    },
}


AUTHENTICATION_BACKENDS = (
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.twitter.TwitterOAuth',
    'social_core.backends.facebook.FacebookOAuth2',

    'django.contrib.auth.backends.ModelBackend',
)


post_reset_login_backend = "django.contrib.auth.backends.RemoteUserBackend"

LOGIN_URL = 'login'
LOGOUT_URL = 'logout'
LOGIN_REDIRECT_URL = 'home'

# fundoonote id and secret key for github
SOCIAL_AUTH_GITHUB_KEY = os.getenv("SOCIAL_AUTH_GITHUB_KEY")
SOCIAL_AUTH_GITHUB_SECRET = os.getenv("SOCIAL_AUTH_GITHUB_SECRET")

# fundoonote id and secret key for Facebook
SOCIAL_AUTH_FACEBOOK_KEY = os.getenv("SOCIAL_AUTH_FACEBOOK_KEY")  # App ID
SOCIAL_AUTH_FACEBOOK_SECRET = os.getenv("SOCIAL_AUTH_FACEBOOK_SECRET")  # App Secret


# Homepage URL = http://127.0.0.1:8000
# Authorization callback URL = http://localhost:8000

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'fundoonote/static'),
]
# AWS_ACCESS_KEY_ID = 'AKIAU6YF2KSOPYML3SMB'
# AWS_SECRET_ACCESS_KEY = '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'
# AWS_STORAGE_BUCKET_NAME = 'fundoonote-bucket'
# AWS_S3_CUSTOM_DOMAIN = '%s.s3.amazonaws.com' % AWS_STORAGE_BUCKET_NAME
#
# AWS_S3_OBJECT_PARAMETERS = {
#     'CacheControl': 'max-age=86400',
# }
#
# AWS_LOCATION = 'static'
# STATICFILES_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
# STATIC_URL = "https://%s/%s/" % (AWS_S3_CUSTOM_DOMAIN, AWS_LOCATION)
#
# DEFAULT_FILE_STORAGE = 'fundoonote.storage_backends.MediaStorage'

# CELERY STUFF
BROKER_URL = 'redis://localhost:6379'
CELERY_RESULT_BACKEND = 'redis://localhost:6379'
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Africa/Nairobi'

# Notifications
NOTIFICATIONS_PAGINATE_BY = 15
NOTIFICATIONS_USE_WEBSOCKET = False
NOTIFICATIONS_RABBIT_MQ_URL = 'amqp://guest:guest@localhost:5672'
NOTIFICATIONS_CHANNELS = {
    'console': 'notifications.channels.ConsoleChannel'
}

CELERY_TASK_ALWAYS_EAGER = True



ELASTICSEARCH_DSL = {
    'default': {
        'hosts': 'localhost:9200'
    },
}