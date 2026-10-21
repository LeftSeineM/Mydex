"""Interactive-user lifecycle; never rebinds WeChat or repeats uncertain sends."""
import argparse
from contextlib import closing, redirect_stdout
from datetime import datetime, timezone
import io
import json
import msvcrt
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import winreg
import psutil

BUNDLE = Path(__file__).resolve().parents[1]
APP = BUNDLE / 'app'
DATA = APP / '.local/quote-m-session'
STATUS = DATA / 'deployment-status.json'
STOP = DATA / 'stop.request'
NAME = 'MydexAccountAssistant'
RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
STALE_RUNTIME_SECONDS = 180


def report(phase, **fields):
    DATA.mkdir(parents=True, exist_ok=True)
    value = {'phase': phase, 'at': datetime.now(timezone.utc).isoformat(), **fields}
    tmp = STATUS.with_suffix('.tmp')
    for attempt in range(6):
        try:
            tmp.write_text(json.dumps(value, indent=2), encoding='utf-8')
            tmp.replace(STATUS)
            break
        except PermissionError:
            # Windows readers can briefly deny rename. A status write must not
            # orphan the healthy child; the next monitor cycle will try again.
            if attempt == 5:
                value['status_write_deferred'] = True
                break
            time.sleep(.05 * (attempt + 1))
    return value


def ready():
    import preflight
    with redirect_stdout(io.StringIO()):
        if preflight.main() != 0:
            return False
    path = DATA / 'history.sqlite3'
    if path.exists():
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'outbox' in tables and db.execute("SELECT 1 FROM outbox WHERE state IN ('sending','unknown') LIMIT 1").fetchone():
                return False
            if 'send_circuit' in tables and db.execute('SELECT 1 FROM send_circuit LIMIT 1').fetchone():
                return False
            if 'send_attempts' in tables and db.execute("SELECT 1 FROM send_attempts WHERE outcome IN ('reserved','sending','unknown') LIMIT 1").fetchone():
                return False
    return True


def uncertain_delivery():
    path = DATA / 'history.sqlite3'
    if not path.exists():
        return False
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return bool(('outbox' in tables and db.execute(
            "SELECT 1 FROM outbox WHERE state IN ('sending','unknown') LIMIT 1").fetchone())
            or ('send_attempts' in tables and db.execute(
                "SELECT 1 FROM send_attempts WHERE outcome IN ('reserved','sending','unknown') LIMIT 1").fetchone()))


def runtime_stalled(state, started_at, now):
    return (state.get('phase') == 'running' and started_at <= state.get('at', 0)
            and now - state['at'] > STALE_RUNTIME_SECONDS)


def command():
    pythonw = Path(sys.executable).with_name('pythonw.exe')
    return subprocess.list2cmdline([str(pythonw), '-B', str(Path(__file__).resolve()), 'run'])


def supervisor_running():
    expected = str(Path(__file__).resolve()).lower()
    for proc in psutil.process_iter(['name', 'cmdline']):
        args = proc.info['cmdline'] or []
        if ((proc.info['name'] or '').lower() in ('python.exe', 'pythonw.exe')
                and 'run' in args and expected in [arg.lower() for arg in args]):
            return True
    return False


def wait_for_supervisor_exit(timeout=30):
    deadline = time.monotonic() + timeout
    while supervisor_running():
        if time.monotonic() >= deadline:
            return False
        time.sleep(.2)
    return True


def run():
    DATA.mkdir(parents=True, exist_ok=True)
    with (DATA / 'deployment.lock').open('a+b') as lock:
        lock.seek(0)
        lock.write(b'0')
        lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return
        attempts = []
        while not STOP.exists():
            try:
                valid = ready()
            except Exception:
                valid = False
            if not valid:
                report('needs_revalidation', automatic_rebind=False)
                return
            attempts = [t for t in attempts if time.time() - t < 3600]
            if len(attempts) >= 3:
                report('needs_attention', reason='restart_limit')
                return
            attempts.append(time.time())
            logs = []
            for name in ('runtime.stdout.log', 'runtime.stderr.log'):
                path = DATA / name
                if path.exists() and path.stat().st_size > 2_000_000:
                    path.replace(path.with_suffix('.log.1'))
                logs.append(path.open('ab'))
            try:
                child = subprocess.Popen([sys.executable, '-B', '-u', str(APP / 'account_assistant.py')],
                    cwd=APP, stdin=subprocess.DEVNULL, stdout=logs[0], stderr=logs[1],
                    creationflags=subprocess.CREATE_NO_WINDOW)
                report('starting', restart_count=len(attempts) - 1)
                stalled_recovery = False
                while child.poll() is None:
                    if STOP.exists():
                        report('stopping')
                    else:
                        state_path = DATA / 'assistant-status.json'
                        if state_path.exists():
                            state = json.loads(state_path.read_text(encoding='utf-8'))
                            # A Windows venv launcher can create a second Python PID.
                            if state.get('at', 0) >= attempts[-1]:
                                try:
                                    runner = psutil.Process(state['runner_pid'])
                                    matches = str(APP / 'account_assistant.py').lower() in [arg.lower() for arg in runner.cmdline()]
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    matches = False
                                if matches:
                                    report(state.get('phase', 'starting'), restart_count=len(attempts) - 1)
                                    if runtime_stalled(state, attempts[-1], time.time()):
                                        uncertain = uncertain_delivery()
                                        report('checking_recovery', reason='runtime_stalled')
                                        runner.terminate()
                                        try:
                                            child.wait(timeout=10)
                                        except subprocess.TimeoutExpired:
                                            child.terminate()
                                            child.wait(timeout=10)
                                        if uncertain:
                                            report('needs_attention', reason='stalled_with_uncertain_send')
                                            return
                                        stalled_recovery = True
                                        break
                    time.sleep(3)
                if STOP.exists():
                    report('stopped')
                    return
                if child.returncode == 0 and not stalled_recovery:
                    report('needs_attention', reason='runner_exited_requires_review')
                    return
                report('checking_recovery', exit_code=child.returncode)
                time.sleep(10)
            finally:
                for log in logs:
                    log.close()
        report('paused')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'stop', 'status', 'run', 'enable-autostart', 'disable-autostart'])
    action = parser.parse_args().action
    DATA.mkdir(parents=True, exist_ok=True)
    if action == 'run':
        run()
    elif action == 'start':
        if STOP.exists():
            # The old supervisor must observe STOP before a new start clears it.
            if not wait_for_supervisor_exit():
                print('Previous supervisor is still stopping; stop request preserved.')
                return 2
        elif supervisor_running():
            print('Supervisor is already running; no additional process launched.')
            return 0
        if not ready():
            print(json.dumps(report('needs_revalidation', automatic_rebind=False)))
            return 2
        STOP.unlink(missing_ok=True)
        subprocess.Popen(command(), cwd=BUNDLE, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        print('Launch requested; use status to verify readiness.')
    elif action == 'stop':
        STOP.write_text('Operator requested stop. Explicit start required.\n', encoding='utf-8')
        print('Stop requested. Active sends are not retried; use status to confirm stopped.')
    elif action == 'status':
        value = json.loads(STATUS.read_text(encoding='utf-8')) if STATUS.exists() else {'phase': 'not_started'}
        value['stop_requested'] = STOP.exists()
        runtime_path = DATA / 'assistant-status.json'
        if runtime_path.exists():
            runtime = json.loads(runtime_path.read_text(encoding='utf-8'))
            age = time.time() - runtime['at']
            value['runtime_status_age_seconds'] = round(age, 1)
            try:
                proc = psutil.Process(runtime['runner_pid'])
                live = str(APP / 'account_assistant.py').lower() in [arg.lower() for arg in proc.cmdline()]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                live = False
            value['runner_alive'] = live
            if live and age < 10:
                value['phase'] = runtime['phase']
            elif value['phase'] == 'running':
                value['phase'] = 'runtime_status_stale'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            try:
                value['autostart_enabled'] = winreg.QueryValueEx(key, NAME)[0] == command()
            except FileNotFoundError:
                value['autostart_enabled'] = False
        print(json.dumps(value))
    else:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            try:
                existing = winreg.QueryValueEx(key, NAME)[0]
            except FileNotFoundError:
                existing = None
            if existing and existing != command():
                raise ValueError('Startup entry belongs to a different deployment')
            if action == 'enable-autostart':
                winreg.SetValueEx(key, NAME, 0, winreg.REG_SZ, command())
            elif existing:
                winreg.DeleteValue(key, NAME)
        print(action + ': done')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        DATA.mkdir(parents=True, exist_ok=True)
        with (DATA / 'supervisor.errors.log').open('a', encoding='utf-8') as log:
            log.write(datetime.now(timezone.utc).isoformat() + ' ' + type(exc).__name__ + '\n')
        report('needs_attention', reason='supervisor_error', error_type=type(exc).__name__)
        raise SystemExit(1)
