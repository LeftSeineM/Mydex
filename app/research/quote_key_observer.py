"""Reuse the verified callback observer for M's isolated two-file profile."""
import json
from pathlib import Path
import time
import psutil
import run_key_observer as observer
from inspect_open_databases import inventory

DATA=Path(__file__).resolve().parents[1]/'.local/quote-m-session'

def main():
    session=json.loads((DATA/'session.json').read_text(encoding='utf-8'))
    pid=session['pid']
    if psutil.Process(pid).create_time()!=session['created']:raise ValueError('Session changed')
    roots=set()
    for raw in inventory(pid)['database_paths']:
        for parent in Path(raw).parents:
            if parent.name=='db_storage':roots.add(str(parent.parent))
    if roots!=set(session['account_roots']):raise ValueError('Account changed')
    observer.DATA=DATA
    report,_=observer.start(pid)
    observer.save(report)
    print(json.dumps({'phase':report['phase'],'pid':pid,'authenticated_databases':report['authenticated_databases']}),flush=True)
    expected=observer.pages()
    try:
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            report,_=observer.existing(pid,expected=expected)
            observer.save(report)
            if report['authenticated_databases']==len(expected):break
            time.sleep(2)
    finally:
        final,_=observer.existing(pid,stop=True,expected=expected)
        observer.save(final)
        print(json.dumps({'phase':final['phase'],'authenticated_databases':final['authenticated_databases'],
                          'native_candidates_cleared':final['native_candidates_cleared']}),flush=True)

if __name__=='__main__':main()
