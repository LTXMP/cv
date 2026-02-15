import os

workers = int(os.environ.get('WEB_CONCURRENCY', 1))
threads = int(os.environ.get('GUNICORN_THREADS', 4))
timeout = 120
bind = os.environ.get('GUNICORN_BIND', '0.0.0.0:10000')
forwarded_allow_ips = '*'
secure_scheme_headers = {'X-Forwarded-Proto': 'https'}
