"""Read-only compatibility check. Never sends messages or dumps chat contents."""
import importlib.metadata
import json
import sys


def probe():
    result = {"python": sys.version.split()[0], "connected": False}
    try:
        result["library"] = importlib.metadata.version("wxauto4")
        from wxauto4 import WeChat
        wx = WeChat(resize=False)
        info = wx.ChatInfo()
        result.update(connected=True, chat_type=info.get("chat_type"),
                      methods={n: callable(getattr(wx, n, None)) for n in
                               ("ChatInfo", "GetAllMessage", "SendMsg")})
    except Exception as exc:
        result.update(error_type=type(exc).__name__, error=str(exc)[:600])
    print("LAB_PROBE=" + json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    probe()
