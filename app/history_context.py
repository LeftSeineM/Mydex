"""Group-scoped history retrieval and exact counts over locally archived rows.
Aggregate results never claim complete WeChat history. No model-generated SQL.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone
import heapq
import re
import time

CN = timezone(timedelta(hours=8))
HISTORY = re.compile(r'之前|以前|曾经|上次|当时|往事|历史|昨[天晚夜]|前天|今天|今晚|上周|这周|本周|最近|聊过|说过|记得|群里|群友|群聊|聊天记录|谁.*(?:最|多|少)|统计|总结|回顾')
BOT = re.compile(r'^(?:Mydex|小研|M)[：:]')


def query_plan(question, now):
    clean = re.sub(r'@[^\s]+\s*', '', question).strip()
    current = datetime.fromtimestamp(now, CN)
    midnight = current.replace(hour=0, minute=0, second=0, microsecond=0)
    start = end = None
    label = ''
    if re.search(r'昨晚|昨夜|昨天晚上', clean):
        start, end = midnight-timedelta(hours=6), midnight
        label = '昨晚：北京时间前一天18:00至24:00'
    elif '前天' in clean:
        start, end = midnight-timedelta(days=2), midnight-timedelta(days=1)
        label = '前天（北京时间）'
    elif '昨天' in clean:
        start, end = midnight-timedelta(days=1), midnight
        label = '昨天（北京时间）'
    elif '今天' in clean or '今晚' in clean:
        start, end = midnight, current+timedelta(seconds=1)
        if '今晚' in clean:start=midnight+timedelta(hours=18)
        label = '今天/今晚（北京时间）'
    elif '上周' in clean:
        end = midnight-timedelta(days=midnight.weekday())
        start = end-timedelta(days=7)
        label = '上周：北京时间周一至周日'
    elif '本周' in clean or '这周' in clean:
        start, end = midnight-timedelta(days=midnight.weekday()),current+timedelta(seconds=1)
        label = '本周（北京时间）'
    explicit = re.search(r'(20\d\d)[年/-](\d{1,2})[月/-](\d{1,2})日?',clean)
    if explicit:
        try:
            start=datetime(*(int(x) for x in explicit.groups()),tzinfo=CN)
            end=start+timedelta(days=1);label='指定日期（北京时间）'
        except ValueError:pass
    laugh = bool(re.search(r'哈哈|连续.*哈',clean) and re.search(r'谁|哪位|统计|次数|多少|最多|最爱',clean))
    speakers = bool(re.search(r'谁|哪位|统计|排名',clean) and re.search(r'话最多|发言|发消息|消息.*多|活跃|发了多少',clean))
    historical = bool(HISTORY.search(clean) or explicit or laugh or speakers)
    stripped = re.sub(r'之前|以前|曾经|上次|当时|往事|历史|昨天|昨晚|昨夜|前天|今天|今晚|上周|本周|这周|最近|我们|大家|你们|群里面|群里|群友|群聊|聊天记录|记录|聊过|聊了|聊天|聊|说过|讨论|总结|回顾|归纳|梳理|帮我|帮忙|一下|关于|哪些|有什么|什么|事情|情况|内容|话题|能不能|可以|请你|请|的|了|吗|呢|记得|还记得', ' ',clean)
    stripped=re.sub(r'20\d\d[年/-]\d{1,2}[月/-]\d{1,2}日?',' ',stripped)
    tokens=[]
    for part in re.findall(r'[\u4e00-\u9fff]{2,}|[A-Za-z][A-Za-z0-9+._-]{1,}',stripped):
        if len(part)<=12:tokens.append(part)
        if re.search(r'[\u4e00-\u9fff]',part):tokens.extend(part[n:n+2] for n in range(len(part)-1))
    return {'historical':historical,'start':start.timestamp() if start else None,
            'end':end.timestamp() if end else None,'time_label':label,
            'metric':'laugh_messages' if laugh else 'message_count' if speakers else None,
            'tokens':list(dict.fromkeys(tokens))[:24]}


def retrieve(store, source, room, question, event_id, limit=500, now=None):
    plan=query_plan(question,time.time() if now is None else now)
    if not plan['historical']:return None
    sql="SELECT * FROM messages WHERE source=? AND room=? AND role='user' AND event_id<>?"
    values=[source,room,event_id]
    if plan['start'] is not None:
        sql+=' AND COALESCE(message_time,created)>=? AND COALESCE(message_time,created)<?'
        values.extend([plan['start'],plan['end']])
    counts=Counter();total=0;matches=0;first=None;last=None;selected=[]
    with store.lock:
        for raw in store.db.execute(sql,values):
            row=dict(raw);content=row['content'];stamp=row['message_time'] or row['created']
            if BOT.match(content):continue
            total+=1;first=stamp if first is None else min(first,stamp);last=stamp if last is None else max(last,stamp)
            if plan['metric']:
                match=plan['metric']=='message_count' or bool(re.search(r'哈{2,}',content))
                if match:counts[row['sender']]+=1
                score=1
            elif plan['tokens']:
                lowered=content.casefold()
                score=sum(len(t) for t in plan['tokens'] if t.casefold() in lowered)
                match=score>0
            else:match=True;score=1
            if not match:continue
            matches+=1
            item=(score,stamp,row['row_id'],row)
            if len(selected)<limit:heapq.heappush(selected,item)
            elif item[:3]>selected[0][:3]:heapq.heapreplace(selected,item)
    rows=[x[3] for x in sorted(selected,key=lambda x:x[:3],reverse=True)]
    details={'history_completeness':'unknown','query_time_label':plan['time_label'] or '本群本机已归档历史',
             'query_start':datetime.fromtimestamp(plan['start'],CN).isoformat() if plan['start'] else None,
             'query_end_exclusive':datetime.fromtimestamp(plan['end'],CN).isoformat() if plan['end'] else None,
             'searched_user_messages':total,'matched_messages':matches,
             'first_available_time':datetime.fromtimestamp(first,CN).isoformat() if first else None,
             'last_available_time':datetime.fromtimestamp(last,CN).isoformat() if last else None,
             'retrieved_evidence_messages':len(rows),'older_messages_omitted':matches>len(rows)}
    if plan['metric']:
        from member_labels import display_sender
        details['statistics']={'metric':plan['metric'],
              'definition':'正文含连续两个及以上“哈”的消息条数（按字面匹配）' if plan['metric']=='laugh_messages' else '已归档群消息条数，含非文字消息占位记录，不含助手回复',
              'counted_over_all_searched_rows':True,'matched_messages':sum(counts.values()),
              'ranking':[{'member':display_sender(sender,room),'count':count} for sender,count in counts.most_common(30)],
              'ranking_omitted_members':max(0,len(counts)-30)}
    return rows,details


def compose(store, source, room, question, event_id, cfg, now=None):
    """Prioritize retrieved evidence; always put the actual new question last."""
    found=retrieve(store,source,room,question,event_id,cfg['summary_messages'],now)
    if found is None:
        return store.context(source,room,cfg['history_turns']*2,cfg['summary_max_chars'])
    candidates,details=found
    recent,scope=store.context(source,room,min(cfg['history_turns']*2,12),cfg['summary_max_chars'])
    with store.lock:
        raw=store.db.execute("SELECT * FROM messages WHERE source=? AND room=? AND event_id=? AND role='user'",
                             (source,room,event_id)).fetchone()
    current=dict(raw) if raw else None
    if current and len(current['content'])+len(current['sender'])+120>cfg['summary_max_chars']:
        current['content']=current['content'][:cfg['summary_max_chars']-300]+'【提问过长，已截断】'
    ordered=([current] if current else [])+candidates
    # A dated request should not be polluted by newer, unrelated discussions.
    if details['query_start'] is None:ordered+=list(reversed(recent))
    used=0;selected={}
    for row in ordered:
        if row['row_id'] in selected:continue
        cost=len(row['content'])+len(row['sender'])+120
        if used+cost>cfg['summary_max_chars']:continue
        selected[row['row_id']]=row;used+=cost
    rows=sorted(selected.values(),key=lambda r:(r['message_time'] or r['created'],r['row_id']))
    if current and current['row_id'] in selected:
        rows=[r for r in rows if r['row_id']!=current['row_id']]+[current]
    evidence_ids={r['row_id'] for r in candidates}
    included=sum(r['row_id'] in evidence_ids for r in rows)
    scope.update(details,included_messages=len(rows),included_evidence_messages=included,
                 evidence_omitted=details['matched_messages']>included,
                 first_included_time=min((r['message_time'] or r['created'] for r in rows),default=None),
                 last_included_time=max((r['message_time'] or r['created'] for r in rows),default=None))
    return rows,scope
