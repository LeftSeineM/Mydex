"""Only the sample-bound group's rows from authenticated local message shards.
No replies are triggered by imports. Compressed text is decoded with a bound.
"""
from datetime import datetime,timezone
import hashlib,json,re
from pathlib import Path
import sys,time
import zstandard
from history_crypto import dpapi
from history_vfs import HistoryView,SnapshotChanged
from run_native_observer import ROOT
sys.path.insert(0,str(ROOT))
from lab import Engine,Settings,Store
def text_value(value):
    if value is None:return ''
    if isinstance(value,str):return value
    if not isinstance(value,bytes):raise ValueError('Unsupported content type')
    if value.startswith(b'\x28\xb5\x2f\xfd'):
        value=zstandard.ZstdDecompressor().decompress(value,max_output_size=1048576)
    if len(value)>1048576:raise ValueError('Message content exceeds bound')
    return value.decode('utf-8',errors='strict')
def read(import_records=False):
    evidence=json.loads((ROOT/'.local/outbound-sample-evidence.json').read_text(encoding='utf-8-sig'))
    room=evidence['room_id_candidate'];table='Msg_'+hashlib.md5(room.encode()).hexdigest()
    private=json.loads(dpapi((ROOT/'.local/history-keys.dpapi').read_bytes(),True))
    schema=json.loads((ROOT/'.local/history-schema.json').read_text(encoding='utf-8'))
    actual=next((r.get('nick_name') for f in schema['files'] for r in f.get('target_contact',[]) if r.get('username')==room),None)
    if not actual:raise ValueError('Native group name was not read')
    settings=Settings();cfg=settings.get();configured_group=cfg['group']
    if configured_group not in (evidence['group_name'],actual):raise ValueError('Current settings point to another group')
    records=[];attachments=[];files=[];rejections=[]
    allowed={str(Path(row['parent'])/row['name']) for row in json.loads((ROOT/'.local/history-file-profile.json').read_text())}
    authenticated=[entry for entry in private['files'] if re.fullmatch(r'message_\d+\.db',Path(entry['path']).name) and entry['path'] in allowed]
    for item in authenticated:
        path=Path(item['path'])
        for attempt in range(3):
            try:
                with HistoryView(path,bytes.fromhex(item['key']),bytes.fromhex(item['salt'])) as view:
                    exists=view.query('SELECT name FROM sqlite_master WHERE type=? AND lower(name)=lower(?)',('table',table))
                    if not exists:files.append({'name':path.name,'target_table':False});break
                    count=view.query('SELECT COUNT(*) FROM "'+table+'"')[0][0]
                    rows=view.query('SELECT m.local_id,m.server_id,m.local_type,m.create_time,n.user_name,'
                                    'm.message_content,m.compress_content,m.WCDB_CT_message_content,m.source '
                                    'FROM "'+table+'" AS m LEFT JOIN Name2Id AS n ON n.rowid=m.real_sender_id '
                                    'ORDER BY m.sort_seq DESC,m.local_id DESC LIMIT 10000')
                    file_records=[];file_attachments=[];file_rejections=[]
                    for local_id,server_id,kind,created,sender,content,compressed,compression,source in reversed(rows):
                        event_id=str(server_id) if server_id else path.name+':'+str(local_id)
                        try:
                            body=text_value(content) or text_value(compressed)
                            if sender and body.startswith(sender+':\n'):body=body[len(sender)+2:]
                            message_kind=kind&0xffffffff
                            if message_kind not in (1,49):continue
                            if not sender or not body:raise ValueError('Missing sender or text')
                            if message_kind==49:
                                file_attachments.append({'id':event_id,'sender':sender,'created':created,
                                                         'content':body,'kind':kind})
                                continue
                            if len(body)>8000:body=body[:7800]+'【该条历史消息超过长度限制，已截断】'
                            file_records.append({'source':'wechat','room':configured_group,'sender':sender,
                                                 'content':body,'id':event_id,'created':created,'type':'text'})
                        except (ValueError,UnicodeDecodeError,zstandard.ZstdError) as exc:
                            file_rejections.append({'id':event_id,'reason':type(exc).__name__})
                    files.append({'name':path.name,'target_table':True,'stored_rows':count,'rows_read':len(rows),
                                  'text_records':len(file_records),'app_messages':len(file_attachments),'pages_read':view.snapshot.pages_read})
                    records.extend(file_records);attachments.extend(file_attachments);rejections.extend(file_rejections);break
            except SnapshotChanged:
                if attempt==2:files.append({'name':path.name,'error':'snapshot_changed'})
                time.sleep(.1)
    records.sort(key=lambda r:(r['created'],r['id']))
    export={'group_name':actual,'room_id':room,'records':records,'app_messages':attachments,'rejections':rejections}
    (ROOT/'.local/target-group-history.json').write_text(json.dumps(export,ensure_ascii=False,indent=2),encoding='utf-8')
    report={'at':datetime.now(timezone.utc).isoformat(),'actual_group_name':actual,'files':files,
            'text_records':len(records),'app_messages':len(attachments),'decode_rejections':len(rejections),
            'history_completeness':'unknown','older_shards_authenticated':len(authenticated)==4,
            'test_markers_found':{marker:sum(marker in r['content'] for r in records) for marker in ('WXPAIR1006','WXRECV1006')},
            'first_message_time':records[0]['created'] if records else None,'last_message_time':records[-1]['created'] if records else None,
            'replies_created':0}
    if import_records:
        store=Store();engine=Engine(settings,store)
        try:
            total={'added':0,'skipped':0,'replies_created':0}
            for offset in range(0,len(records),2000):
                result=engine.record_history(records[offset:offset+2000]);total['added']+=result['added'];total['skipped']+=result['skipped']
            report['import']=total
        finally:store.db.close()
    (ROOT/'.local/history-read-status.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    return report
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--import-records',action='store_true')
    print(json.dumps(read(parser.parse_args().import_records),ensure_ascii=False))
