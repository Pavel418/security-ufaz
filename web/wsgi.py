"""
WSGI entrypoint. In production, point your server (gunicorn/uwsgi) here:

    gunicorn 'wsgi:app' --bind 0.0.0.0:5000
"""

from netapp import create_app

app = create_app()