"""
ASGI config for mypika project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application
import django
#from socketio import ASGIApp
import socketio

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mypika.settings')
django.setup()  # make sure Django apps are loaded first

# Import AFTER setup
from pika.socket_handlers import sio  # ✅ now safe

django_asgi_application = get_asgi_application()

#for websocket (socket.io) config
application = socketio.ASGIApp(sio, django_asgi_application, socketio_path="socket.io")
