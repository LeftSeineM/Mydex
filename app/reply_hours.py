"""Daily reply window for the account assistant (Asia/Shanghai)."""
from datetime import datetime, timedelta, timezone

LOCAL_ZONE = timezone(timedelta(hours=8))


def replies_allowed(now=None):
    current = now or datetime.now(LOCAL_ZONE)
    return current.astimezone(LOCAL_ZONE).hour >= 7
