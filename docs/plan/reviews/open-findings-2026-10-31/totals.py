# usage: git show <ref>:docs/plan/11-backlog.md | python3 -I totals.py
import sys,re,collections
rows=collections.defaultdict(lambda:[0,0.0,0.0])
ids=set()
for l in sys.stdin:
    if not re.match(r'^\| M\d-\d{3} \|',l): continue
    c=[x.strip() for x in l.strip().strip('|').split('|')]
    if len(c)<7 or not re.match(r'^M\d$',c[1]): continue
    if c[0] in ids: print('DUP',c[0]); continue
    ids.add(c[0]); m=c[1]
    try: h=float(c[4])
    except Exception: print('BADH',c[0],c[4]); continue
    r=rows[m]; r[0]+=1; r[1]+=h
    if m!='M1' or c[5]=='yes': r[2]+=h
t=[0,0,0]
for m in sorted(rows):
    r=rows[m]; print(m,r[0],r[1],r[2]); t=[a+b for a,b in zip(t,r)]
print('All',*t)
