"""Branch-aware constant/stack audit of known FO27Q3 HDR-record addresses.

Call targets, stack prologues and aligned odd code pointers in data seed unknown
entry states. Conditional branches
explore both edges, joins retain only equal constants. Calls clobber caller-saved
registers; stack cells and s0/s1 are assumed ABI-preserved. Indirect jumps stop.
No interprocedural argument, computed-alias, or CPU emulation proof is implied.
"""
from collections import deque
import json,re
from trace_mips import ROOT,load

BASE=0x86000000; END=BASE+0xe7ff8; LO=0xa0101a74; HI=LO+5
rows={r['address']:r for r in load('FO27Q3') if r['address']<END}
addresses=sorted(rows); following=dict(zip(addresses,addresses[1:]))
def destination(args):
 m=re.search(r'0x[0-9a-f]+$',args)
 return int(m[0],16)&~1 if m else None
roots={BASE}
for a,r in rows.items():
 if r['op'] in ('jal','jalx') and destination(r['args']) in rows:roots.add(destination(r['args']))
 if r['op']=='addiu' and re.fullmatch(r'sp,-\d+',r['args']):roots.add(a)
firmware=(ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/F05.bin').read_bytes()
pointer_roots=set()
for i in range(0xe8000,len(firmware)-3,4):
 p=int.from_bytes(firmware[i:i+4],'little')
 if p&1 and BASE<=p<END and (p&~1)in rows:pointer_roots.add(p&~1)
roots.update(pointer_roots)
states={a:{'sp':0x10000000} for a in roots}; queue=deque(roots)
no_write={'sw','sb','sh','cmp','cmpi','slt','sltu','slti','sltiu','div','divu','mult','multu','nop'}
conditional={'beqz','bnez','btnez','bteqz'}
memory=re.compile(r'(\w+),(-?\d+)\((\w+)\)')

def step(r,source):
 s=source.copy();op=r['op'];p=r['args'].split(',');dest=p[0];value=None
 m=memory.fullmatch(r['args'])
 if op in ('jal','jalx'):
  for k in ('v0','v1','a0','a1','a2','a3','t8','ra'):s.pop(k,None)
  return s
 try:
  if op=='lui':value=int(p[1],0)<<16
  elif op=='li':value=int(p[1],0)
  elif op=='move':value=s.get(p[1])
  elif op=='addiu':
   reg=dest if len(p)==2 else p[1]
   if reg in s:value=s[reg]+int(p[-1],0)
  elif op in ('addu','subu','and','or','xor'):
   lhs,rhs=(dest,p[1])if len(p)==2 else(p[1],p[2])
   if lhs in s and rhs in s:
    x,y=s[lhs],s[rhs]
    value={'addu':lambda:x+y,'subu':lambda:x-y,'and':lambda:x&y,'or':lambda:x|y,'xor':lambda:x^y}[op]()
  elif op in ('sll','srl'):
   reg=dest if len(p)==2 else p[1]
   if reg in s:value=s[reg]<<int(p[-1],0)if op=='sll' else s[reg]>>int(p[-1],0)
  elif op in ('neg','not'):
   reg=dest if len(p)==1 else p[1]
   if reg in s:value=-s[reg] if op=='neg' else ~s[reg]
  elif op=='lw' and m and m[3]=='sp' and 'sp' in s:
   value=s.get('@'+hex(s['sp']+int(m[2])))
  if op in ('sw','sb','sh') and m and m[3]=='sp' and 'sp' in s:
   slot='@'+hex(s['sp']+int(m[2]));s.pop(slot,None)
   if op=='sw' and m[1] in s:s[slot]=s[m[1]]
 except (ValueError,IndexError):pass
 if op not in no_write and op not in conditional and op not in ('jr','j','b'):
  s.pop(dest,None)
  if value is not None:s[dest]=value&0xffffffff
 return s

iterations=0
while queue:
 a=queue.popleft();r=rows[a];out=step(r,states[a]);op=r['op']
 if op in ('jr','j'):successors=[]
 elif op=='b':successors=[destination(r['args'])]
 elif op in conditional:successors=[following.get(a),destination(r['args'])]
 else:successors=[following.get(a)]
 for b in successors:
  if b not in rows:continue
  if b in states:
   merged={k:v for k,v in states[b].items()if k in out and out[k]==v}
   if merged==states[b]:continue
  else:merged=out.copy()
  states[b]=merged;queue.append(b)
 iterations+=1

refs=[];bulk=[]
for a,s in sorted(states.items()):
 r=rows[a];op=r['op'];m=memory.fullmatch(r['args'])
 if m and m[3] in s:
  addr=(s[m[3]]+int(m[2]))&0xffffffff
  width={'lw':4,'sw':4,'lh':2,'lhu':2,'sh':2,'lbu':1,'lb':1,'sb':1}.get(op,0)
  if width and addr<HI and addr+width>LO:
   refs.append(dict(file_offset=hex(a-BASE),ram=hex(addr),width=width,op=op,instruction=r['line']))
 if op in ('jal','jalx'):
  args={k:hex(s[k])for k in ('a0','a1','a2','a3')if k in s}
  if any(LO<=s.get(k,0)<HI for k in args):
   refs.append(dict(file_offset=hex(a-BASE),op='call_argument',args=args,instruction=r['line']))
  if destination(r['args']) in (BASE+0x2604,BASE+0x2650):
   length=s.get('a2',0)
   for role in ('a0','a1'):
    start=s.get(role,0)
    if 0<length<0x100000 and start<HI and start+length>LO:
     bulk.append(dict(file_offset=hex(a-BASE),role=role,start=hex(start),length=length,instruction=r['line']))
report={'method':__doc__,'root_count':len(roots),'data_pointer_roots':len(pointer_roots),'reached_instructions':len(states),'iterations':iterations,
 'references':refs,'overlapping_known_copy_or_fill_calls':bulk,
 'limitations':['Both conditional edges explored; no condition solving',
 'Indirect jump targets not recovered','Unknown incoming pointers and callee side effects not audited',
 'Constant propagation cannot establish bit ownership or absence of aliases']}
(ROOT/'research/FO27Q3.hdr_cfg_refs.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['root_count','reached_instructions','iterations']}))
print(f'{len(refs)} references; {len(bulk)} overlapping known copy/fill calls. Incomplete alias audit.')
for r in refs:print(r['file_offset'],r.get('ram',r.get('args')),r['op'])
