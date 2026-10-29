# usage: python3 -I resolve.py <file> ours-first|theirs-first  (union of both sides per hunk)
import sys
p,order=sys.argv[1],sys.argv[2]
t=open(p).read()
while '<<<<<<< ' in t:
    a=t.index('<<<<<<< '); a2=t.index('\n',a)+1
    b=t.index('=======\n',a2); c=t.index('>>>>>>> ',b); c2=t.index('\n',c)+1
    ours=t[a2:b]; theirs=t[b+8:c]
    mid = theirs+ours if order=='theirs-first' else ours+theirs
    t=t[:a]+mid+t[c2:]
open(p,'w').write(t)
