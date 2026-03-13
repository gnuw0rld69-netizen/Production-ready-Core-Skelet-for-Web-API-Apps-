import json
import threading
import time
from typing import Any, cast

from redis import Redis
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.redis import get_redis_client
from app.models.user_action_log import UserActionLog


AUDIT_LOG_QUEUE_KEY = "queue:audit:user_actions"
QUEUE_POLL_SECONDS = 1


class AuditService:
    @staticmethod
    def log_user_action(
        db: Session,
        action: str,
        method: str,
        path: str,
        status_code: int,
        success: bool,
        actor_user_id: int | None = None,
        target_user_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        details: str | None = None,
    ) -> None:
        log_entry = UserActionLog(
            action=action,
            method=method,
            path=path,
            status_code=status_code,
            success=success,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )

        db.add(log_entry)
        try:
            db.commit()
        except Exception:
            db.rollback()

    @staticmethod
    def enqueue_user_action(
        action: str,
        method: str,
        path: str,
        status_code: int,
        success: bool,
        actor_user_id: int | None = None,
        target_user_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        details: str | None = None,
        redis_client: Redis | None = None,
    ) -> None:
        payload = {
            "action": action,
            "method": method,
            "path": path,
            "status_code": status_code,
            "success": success,
            "actor_user_id": actor_user_id,
            "target_user_id": target_user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details,
        }
        client = redis_client or get_redis_client()
        try:
            client.rpush(AUDIT_LOG_QUEUE_KEY, json.dumps(payload))
            return
        except Exception:
            pass

        with SessionLocal() as db:
            AuditService.log_user_action(db=db, **payload)

    @staticmethod
    def run_queue_worker(stop_event: threading.Event) -> None:
        client: Any = Redis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            while not stop_event.is_set():
                try:
                    item = cast(
                        tuple[str, str] | None,
                        client.blpop([AUDIT_LOG_QUEUE_KEY], timeout=QUEUE_POLL_SECONDS),
                    )
                except Exception:
                    time.sleep(QUEUE_POLL_SECONDS)
                    continue
                if not item:
                    continue
                _, payload = item
                try:
                    data = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                with SessionLocal() as db:
                    AuditService.log_user_action(db=db, **data)
        finally:
            client.close()
