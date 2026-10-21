"""Consume validated local target-group events. Create drafts, never send.
Startup events enter history without replaying old mentions to the model.
"""
import json
from pathlib import Path
import threading
import xml.etree.ElementTree as ET
from lab import DATA,UserError
def verified_mention(source,receiver):
    if not isinstance(source,str) or len(source)>16384 or '<!DOCTYPE' in source.upper():return False
    try:
        root=ET.fromstring(source)
        values=root.findall('.//atuserlist')
        return any(receiver in (node.text or '').split(',') for node in values)
    except ET.ParseError:return False

class NativeInbox:
    def __init__(self,engine,data=DATA):
        self.engine=engine;self.data=Path(data);self.stop_event=threading.Event();self.thread=None
        self.path=self.data/'receive-sample-events.jsonl';self.offset=0
        self.status={'running':False,'archived':0,'processed':0,'errors':0,'last_error':'',
                     'sending_enabled':False,'history_completeness':'unknown'}
        self.lock=threading.Lock()
    def state(self):
        with self.lock:return dict(self.status)
    def event(self,raw):
        evidence=json.loads((self.data/'outbound-sample-evidence.json').read_text(encoding='utf-8-sig'))
        cfg=self.engine.settings.get()
        if cfg['group']!=evidence['group_name'] or raw.get('room_id')!=evidence['room_id_candidate']:
            raise UserError('原生群标识与当前群配置不一致')
        if raw.get('type')!='text' or not raw.get('id') or not raw.get('sender_id') or not raw.get('receiver_id'):
            raise UserError('原生消息身份或类型未通过验证')
        return {'source':'wechat','room':cfg['group'],'sender':raw['sender_id'],'content':raw['content'],
                'id':raw['id'],'created':raw['created'],'type':'text',
                'is_self':raw['sender_id']==raw['receiver_id'],
                'mention_verified':verified_mention(raw.get('msg_source',''),raw['receiver_id'])}
    def consume(self,historical=False):
        if not self.path.exists():return
        with self.path.open('rb') as stream:
            if stream.seek(0,2)<self.offset:
                self.offset=0;historical=True
            stream.seek(self.offset)
            while not self.stop_event.is_set():
                before=stream.tell();line=stream.readline(131073)
                if not line:break
                if len(line)>131072:raise UserError('原生消息日志单条过长')
                if not line.endswith(b'\n'):stream.seek(before);break
                try:
                    message=self.event(json.loads(line))
                    if historical:
                        result=self.engine.record_history([message])
                        with self.lock:self.status['archived']+=result['added']
                    else:
                        self.engine.process(message)
                        with self.lock:self.status['processed']+=1
                except (UserError,ValueError,KeyError,TypeError) as exc:
                    with self.lock:
                        self.status['errors']+=1
                        self.status['last_error']=str(exc)[:160]
                self.offset=stream.tell()
    def start(self):
        if self.thread and self.thread.is_alive():return
        self.stop_event.clear()
        # Archive backlog first; never replay historic @s after service restarts.
        self.consume(historical=True)
        def loop():
            with self.lock:self.status['running']=True
            try:
                while not self.stop_event.is_set():
                    try:self.consume()
                    except (OSError,UserError) as exc:
                        with self.lock:self.status['errors']+=1;self.status['last_error']=str(exc)[:160]
                    self.stop_event.wait(2)
            finally:
                with self.lock:self.status['running']=False
        self.thread=threading.Thread(target=loop,name='native-group-inbox',daemon=True);self.thread.start()
    def stop(self):
        self.stop_event.set()
