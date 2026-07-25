import os
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "sentinel_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks.scan_tasks"]
)

is_eager = os.getenv("CELERY_TASK_ALWAYS_EAGER", "False").lower() in ["true", "1"]

if is_eager:
    celery_app.conf.update(
        task_always_eager=True,
        task_eager_propagates=True,
        broker_url="memory://",
        result_backend="cache+memory://",
    )
else:
    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
    )
