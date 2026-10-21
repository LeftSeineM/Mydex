"""Continuous local group database monitoring, with no screen automation.

Historical rows are archived without replaying mentions; only newly inserted
messages in previously observed shards may invoke the model and a bound sender.
"""
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import queue
import threading
import time

from lab import DATA, UserError
from send_guard import MentionGate, POLICY, SendHeld


class DatabaseInbox:
    def __init__(self, engine, data=DATA, reader_factory=None, interval=.8, sender=None, scope=None, initial_since=0):
        self.engine = engine
        self.data = Path(data)
        self.reader_factory = reader_factory
        self.interval = interval
        self.sender = sender
        self.scope = scope
        self.initial_since = initial_since
        self.stop_event = threading.Event()
        self.thread = None
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.fingerprints = {}
        self.cursors = {}
        self.status = {'running': False, 'phase': 'not_started', 'archived': 0,
                       'new_messages': 0, 'drafts': 0, 'errors': 0, 'last_error': '',
                       'sending_enabled': False, 'history_completeness': 'unknown',
                       'authenticated_message_shards': 0, 'stored_rows': 0}
        suffix='-'+hashlib.md5(scope.encode()).hexdigest() if scope else ''
        self.output = self.data / ('database-inbox'+suffix+'.json')
        self.events_file = self.data / ('database-group-events'+suffix+'.jsonl')
        self.summary_queue = queue.Queue(POLICY['max_pending_mentions'])
        self.mention_gate = MentionGate()

    def enqueue(self, event):
        reason = self.mention_gate.reason(event)
        if not reason:
            try:
                self.summary_queue.put_nowait(event)
                return
            except queue.Full:
                reason = 'queue_full'
        self.report(last_skip_reason=reason,
                    skipped_mentions=self.state().get('skipped_mentions', 0)+1)

    def state(self):
        with self.lock:
            return dict(self.status)

    def report(self, **fields):
        with self.lock:
            self.status.update(fields, at=datetime.now(timezone.utc).isoformat())
            value = dict(self.status)
        with self.write_lock:
            temp = self.output.with_suffix('.tmp')
            temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
            temp.replace(self.output)

    def summarize(self):
        while not self.stop_event.is_set():
            cfg=self.engine.settings.get()
            if cfg['provider']!='mock' and cfg.get('group_model_authorized') is not True:
                with self.lock:self.status['awaiting_model_authorization']=True
                self.stop_event.wait(.5)
                continue
            with self.lock:self.status['awaiting_model_authorization']=False
            try:
                event = self.summary_queue.get(timeout=.5)
            except queue.Empty:
                continue
            try:
                if (self.stop_event.is_set() or
                        not -5 <= time.time()-event.get('created', 0) <= POLICY['max_draft_age_seconds']):
                    self.report(last_skip_reason='expired_or_stopped')
                    continue
                if self.sender and getattr(self.sender,'guard',None) and self.sender.guard.state()['blocked']:
                    self.report(last_skip_reason='send_circuit_open')
                    continue
                self.report(processing_event_id=event['id'], model_busy=True)
                started = time.monotonic()
                self.report(last_queue_age_seconds=round(max(0, time.time()-event.get('created', time.time())), 2),
                            pending_mentions=self.summary_queue.qsize(), last_model_seconds=None,
                            last_send_seconds=None, last_total_seconds=None)
                result = self.engine.process(event,recorded=True)
                self.report(last_model_seconds=round(time.monotonic()-started, 2))
                with self.lock:
                    self.status['drafts'] += int('draft_id' in result)
                if 'draft_id' in result:
                    self.report(last_draft_id=result['draft_id'])
                    send_started = time.monotonic()
                    self.send_result(result, event)
                    self.report(last_send_seconds=round(time.monotonic()-send_started, 2))
                self.report(last_total_seconds=round(time.monotonic()-started, 2))
            except Exception as exc:
                with self.lock:
                    self.status['last_model_error']=str(exc)[:180] if isinstance(exc,UserError) else type(exc).__name__
                self.fail(exc)
            finally:
                self.report(model_busy=False, processing_event_id=None)
                self.summary_queue.task_done()

    def send_result(self, result, event):
        if (not self.sender or not self.sender.enabled or 'draft_id' not in result
                or event.get('source') != 'wechat'
                or not ((event.get('mention_verified') is True and not event.get('is_self'))
                        or (event.get('visible_mention_authorized') is True and not event.get('is_self'))
                        or (event.get('direct_verified') is True and not event.get('is_self'))
                        or (event.get('conversation_verified') is True and not event.get('is_self') and self.engine.settings.get().get('conversation_enabled') is True)
                        or (event.get('self_command_verified') is True and event.get('is_self') is True))
                or self.stop_event.is_set()
                or not -5 <= time.time()-event.get('created', 0) <= POLICY['max_draft_age_seconds']):
            return
        try:
            outcome = self.sender.send_draft(result['draft_id'])
            self.report(last_send_status=outcome['status'], last_reply_id=outcome.get('reply_event_id'),
                        sending_enabled=True, last_send_error='')
        except SendHeld as exc:
            self.report(last_send_status='held', last_send_error=str(exc)[:180])
        except Exception as exc:
            self.report(last_send_status='unconfirmed', last_send_error=str(exc)[:180] if isinstance(exc,UserError) else type(exc).__name__)

    def fail(self, exc):
        # Never log keys, raw app XML, or an exception containing account paths.
        with self.lock:
            self.status['errors'] += 1
        self.report(last_error=type(exc).__name__, phase='retrying')

    def client_online(self):
        import psutil
        pid = getattr(self.sender, 'pid', None)
        if pid:
            try:
                proc = psutil.Process(pid)
                session = getattr(self.sender, 'session', None)
                if session and proc.create_time() != session['created']:
                    return False
                return proc.is_running() and proc.name().lower() == 'weixin.exe'
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False
        return any((p.info['name'] or '').lower() == 'weixin.exe'
                   for p in psutil.process_iter(['name']))

    def cycle(self, reader):
        group = self.engine.settings.get()['group']
        if group not in reader.aliases:
            raise UserError('Current group differs from binding')
        totals = dict(self.status.get('shard_rows', {}))
        for path in reader.message_paths():
            fingerprint = reader.fingerprint(path)
            if self.fingerprints.get(path) == fingerprint:
                continue
            baseline = path not in self.cursors
            result = reader.fetch(path, group, None if baseline else self.cursors[path])
            events = result['events']
            if baseline:
                for offset in range(0, len(events), 2000):
                    added = self.engine.record_history(events[offset:offset + 2000])['added']
                    with self.lock:
                        self.status['archived'] += added
                # A newly discovered shard is history by default. AccountInbox
                # may admit only verified mentions newer than its runtime cutoff.
                baseline_handler = getattr(self, 'consider_baseline_event', None)
                if baseline_handler is not None:
                    for event in events:
                        baseline_handler(event)
            else:
                for event in events:
                    # Only a newly read plain-text message from the logged-in
                    # account may use this explicit self-test command.
                    if (event.get('is_self') is True and event.get('type') == 'text'
                            and event['content'].startswith('#'+self.engine.settings.get()['bot_name']+' ')):
                        event['self_command_verified'] = True
                with self.events_file.open('a', encoding='utf-8') as stream:
                    for event in events:
                        stream.write(json.dumps(event, ensure_ascii=False) + '\n')
                for event in events:
                    self.engine.record_history([event])
                    self.consider_event(event)
                with self.lock:
                    self.status['new_messages'] += len(events)
                if events:
                    self.report(last_new_message_time=max(e['created'] for e in events),
                                receive_verified=True, last_sender=events[-1]['sender'])
            self.cursors[path] = result['cursor']
            # If a batch is full, query the next batch even if file metadata is unchanged.
            if baseline or result['read_rows'] < 1000:
                self.fingerprints[path] = fingerprint
            totals[Path(path).name] = result['stored_rows']
            with self.lock:
                self.status['errors'] += result['rejected']
        client_online=self.client_online()
        self.report(phase='watching' if client_online else 'client_offline', client_online=client_online,
                    sending_enabled=bool(self.sender and self.sender.enabled),
                    authenticated_message_shards=len(reader.message_paths()),
                    shard_rows=totals, stored_rows=sum(totals.values()),
                    group_name=reader.name, account_id=reader.account, last_error='')

    def consider_event(self, event):
        if (event['type'] in ('text', 'quote') and
                ((event.get('mention_verified') is True and not event.get('is_self'))
                 or event.get('self_command_verified') is True)):
            self.enqueue(event)

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.data.mkdir(parents=True, exist_ok=True)
        self.stop_event.clear()
        self.model_thread = threading.Thread(target=self.summarize, name='database-group-model', daemon=True)
        self.model_thread.start()
        def loop():
            reader = None
            refreshed = 0
            self.report(running=True, phase='initializing')
            try:
                while not self.stop_event.is_set():
                    try:
                        if reader is None:
                            if self.reader_factory is None:
                                from history_reader import TargetHistory
                                reader = TargetHistory(self.data,group=self.engine.settings.get()['group'])
                            else:
                                reader = self.reader_factory()
                            suffix='-'+hashlib.md5(self.scope.encode()).hexdigest() if self.scope else ''
                            binding = self.data / ('group-binding'+suffix+'.json')
                            binding.write_text(json.dumps(reader.binding(), ensure_ascii=False, indent=2), encoding='utf-8')
                        if time.monotonic() - refreshed > 15:
                            reader.refresh_keys()
                            refreshed = time.monotonic()
                        self.cycle(reader)
                    except Exception as exc:
                        self.fail(exc)
                    self.stop_event.wait(self.interval)
            finally:
                self.report(running=False, phase='stopped')
        self.thread = threading.Thread(target=loop, name='local-group-database', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def retry_mention(self,event_id):
        """Explicitly retry a recent captured @ after a setup failure."""
        binding=json.loads((self.data/'group-binding.json').read_text(encoding='utf-8'))
        group=self.engine.settings.get()['group']
        if group not in binding['configured_aliases'] or not self.events_file.exists():
            raise UserError('绑定群或已捕获消息不存在')
        found=None
        with self.events_file.open('rb') as stream:
            for line in stream:
                if len(line)>131072:raise UserError('消息日志超出限制')
                event=json.loads(line)
                if event.get('id')==event_id:found=event
        if not found or found.get('room_id')!=binding['room_id'] or found.get('room')!=group:
            raise UserError('未找到绑定群的该条消息')
        eligible = ((found.get('mention_verified') is True and not found.get('is_self'))
                    or (found.get('self_command_verified') is True and found.get('is_self') is True))
        if not eligible or not -5 <= time.time()-found['created'] <= POLICY['max_draft_age_seconds']:
            raise UserError('只能处理十分钟内已验证的新入站 @')
        result=self.engine.process(found,recorded=True)
        if 'draft_id' in result:
            with self.lock:self.status['drafts']+=1
            self.report(last_draft_id=result['draft_id'],last_model_error='')
            self.send_result(result, found)
        return result
