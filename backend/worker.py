import os
from celery import Celery
celery = Celery("cloud_autopilot", broker=os.getenv("REDIS_URL", "redis://redis:6379/0"))
@celery.task
def health_job(): return {"status":"ok"}
