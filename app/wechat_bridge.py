"""Single explicitly selected WeChat group, UI Automation adapter, preview by default."""
from __future__ import annotations
import importlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import uuid
from lab import ROOT, NO_WINDOW, UserError


class SnapshotCursor:
    """Discard history on startup/discontinuity; preserve repeated appended messages."""
    def __init__(self):
        self.previous = None

    @staticmethod
    def signature(message):
        return tuple(str(message.get(key, "")) for key in ("sender", "content", "attr", "type"))

    def update(self, messages):
        current = [self.signature(m) for m in messages]
        previous, self.previous = self.previous, current
        if previous is None or not previous or not current:
            return []
        for overlap in range(min(len(previous), len(current)), 0, -1):
            if previous[-overlap:] == current[:overlap]:
                return messages[overlap:]
        return []  # UI reset/scroll/uncertain continuity: rebaseline, never replay history.


def compatibility_probe():
    try:
        proc = subprocess.run([sys.executable, str(ROOT / "probe_wechat.py")], cwd=ROOT,
                              capture_output=True, timeout=25, creationflags=NO_WINDOW)
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            if line.startswith("LAB_PROBE="):
                return json.loads(line.removeprefix("LAB_PROBE="))
        return {"connected": False, "error": "探测进程未返回结果，请检查微信库安装"}
    except subprocess.TimeoutExpired:
        return {"connected": False, "error": "微信兼容性探测超过 25 秒，已终止"}


class WeChatBridge:
    def __init__(self, engine):
        self.engine = engine
        self.thread = None
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.commands = queue.Queue(maxsize=20)
        self.status = {"running": False, "phase": "stopped", "message": "尚未连接真实微信", "mode": "preview"}

    def state(self):
        with self.lock:
            return {**self.status, "running": bool(self.thread and self.thread.is_alive())}

    def set_status(self, **fields):
        with self.lock:
            self.status.update(fields)

    def start(self, auto_send=False, module="wxauto4"):
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise UserError("微信监听已经在运行")
            if module not in ("wxauto4", "wxautox4"):
                raise UserError("不支持的微信库")
            self.stop_event.clear()
            self.commands = queue.Queue(maxsize=20)
            self.status.update(phase="connecting", message="检查当前微信窗口…", mode="auto" if auto_send else "preview")
            self.thread = threading.Thread(target=self.run, args=(auto_send, module), daemon=True)
            self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.set_status(phase="stopping" if self.state()["running"] else "stopped", message="已请求停止，当前生成完成后不会自动发送")

    def approve(self, key):
        if not self.state()["running"] or self.stop_event.is_set():
            raise UserError("请先连接正确的微信测试群，再发送草稿")
        self.commands.put_nowait(key)

    @staticmethod
    def verify_target(wx, room):
        info = wx.ChatInfo()
        if not isinstance(info, dict) or info.get("chat_name") != room or info.get("chat_type") != "group":
            raise UserError("当前微信窗口不是配置的测试群。请手动打开准确群名对应的群聊后重连；不会自动搜索或发往其他聊天。")

    def send(self, wx, room, key):
        if self.stop_event.is_set():
            return
        draft = next((d for d in self.engine.store.pending() if d["id"] == key), None)
        if not draft or draft["room"] != room or draft["state"] != "draft":
            return
        self.verify_target(wx, room)
        if not self.engine.store.transition(key, "draft", "sending"):
            return
        try:
            response = wx.SendMsg(draft["content"])
            # None or an undocumented result is ambiguous, never reported as delivered.
            success = (isinstance(response, dict) and response.get("status") == "成功")
            if getattr(response, "success", None) is True:
                success = True
            self.engine.store.transition(key, "sending", "sent" if success else "unknown")
            self.set_status(message="微信库报告发送成功" if success else "已调用发送，回执不明确；请在微信核对，不会自动重发")
        except Exception:
            self.engine.store.transition(key, "sending", "unknown")
            raise UserError("微信发送结果不确定，已停止自动重试，请在群里核对") from None

    def run(self, auto_send, module):
        room = self.engine.settings.get()["group"]
        cursor, session = SnapshotCursor(), uuid.uuid4().hex
        sequence = 0
        try:
            # COM objects and all UI calls belong to this one worker thread.
            import pythoncom
            pythoncom.CoInitialize()
            wx = importlib.import_module(module).WeChat(resize=False)
            self.verify_target(wx, room)
            self.set_status(phase="listening", message="已连接：仅处理启动后新出现的 @ 消息")
            while not self.stop_event.is_set():
                if self.engine.settings.get()["group"] != room:
                    raise UserError("测试群配置已改变，请重新连接")
                self.verify_target(wx, room)
                raw = wx.GetAllMessage()
                if not isinstance(raw, (list, tuple)):
                    raise UserError("微信库没有返回有效消息列表")
                messages = [{"sender": str(getattr(m, "sender", "")), "content": str(getattr(m, "content", "")),
                             "type": str(getattr(m, "type", "")), "attr": str(getattr(m, "attr", ""))} for m in raw]
                for message in cursor.update(messages):
                    if self.stop_event.is_set():
                        break
                    sequence += 1
                    message.update(source="wechat", room=room, id=f"{session}:{sequence}")
                    result = self.engine.process(message)
                    if result.get("draft_id"):
                        self.set_status(message="收到 @ 消息，回复草稿已生成")
                        if auto_send:
                            self.send(wx, room, result["draft_id"])
                while not self.commands.empty() and not self.stop_event.is_set():
                    self.send(wx, room, self.commands.get_nowait())
                self.stop_event.wait(2)
            self.set_status(phase="stopped", message="监听已停止")
        except Exception as exc:
            self.set_status(phase="error", message=str(exc)[:500])
        finally:
            try:
                pythoncom.CoUninitialize()
            except (NameError, Exception):
                pass
