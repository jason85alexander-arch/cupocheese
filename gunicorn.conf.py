# Gunicorn settings for Cup O' Cheese (gunicorn reads ./gunicorn.conf.py automatically;
# the start command may also pass it explicitly with -c gunicorn.conf.py).
import os

bind = "0.0.0.0:" + os.environ.get("PORT", "10000")
# 2 processes x 4 threads: requests no longer queue behind one slow upload/clip.
# Sized for the 0.5 CPU / 512 MB instance (~70 MB per worker).
workers = 2
worker_class = "gthread"
threads = 4
timeout = 60
graceful_timeout = 20
keepalive = 5
# Import the app (and run schema migrations) once in the master before forking workers.
preload_app = True
accesslog = None
errorlog = "-"
