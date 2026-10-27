"""Execute assembled hooks in a limited delay-free MIPS16 semantic harness.

Instructions come from GNU's raw-binary disassembly, not the assembly source.
Hardware/OS services are stubs; this does NOT validate the CPU, flash integrity,
register timing, panel behavior or all stock control flow.
"""
import hashlib,json,re
from trace_mips import ROOT,load

import os
OUT=ROOT/os.environ.get('HOOK_OUT','experimental/FO27Q3_F05_HyperNits')
DELAY=os.environ.get('HOOK_DELAY','none') # none | jump | jump+branch
SITES=[(0xf904,8),(0x1526c,6),(0x11328,6),(0x21514,6),(0x7698,8),(0xd6238,12),(0x20de8,12)]
candidate=(OUT/'F05_HyperNits.bin').read_bytes()
stock=(ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/F05.bin').read_bytes()
def parse(path):
 result={}
 for line in path.read_text().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4} ?)+)\s+([\w.]+)\s*(.*)',line)
  if m:result[int(m[1],16)]=(len(m[2].replace(' ',''))//2,m[3],m[4].strip())
 return result
code=parse(OUT/'candidate_code.asm')
original_code={r['address']:(len(r['raw'].replace(' ',''))//2,r['op'],r['args'])for r in load('FO27Q3')}
symbols={k:int(v,16)for k,v in json.loads((OUT/'build_report.json').read_text())['symbols'].items()}
assert hashlib.sha256(candidate).hexdigest()==json.loads((OUT/'build_report.json').read_text())['output_sha256']
BASE=0x86000000; RAM=0xa0101a74; DESC=0xa0101890; STOP=0x8ffe0000; SP=0x70010000

class Machine:
 def __init__(self,image=candidate,instructions=code,mode=4,hdr=True,raw=0x90,read_ok=True,write_ok=True,navigation=False,sval=1000,f2=1000):
  self.image=image;self.delay=DELAY if image is candidate else 'none';self.code=instructions;self.r={k:0 for k in ('v0','v1','a0','a1','a2','a3','s0','s1','t8','ra','sp')}
  self.r.update(sp=SP,ra=STOP|1,s0=0x1357,s1=0x2468)
  self.mem={};self.mode=mode;self.hdr=hdr;self.read_ok=read_ok;self.write_ok=write_ok;self.navigation=navigation;self.events=[];self.writes=[];self.services=[]
  self.sval=sval;self.f2=f2;self.sel_a0=None;self.gate_calls=[]
  for i in range(4):self.put(0xa0100578+10*i+2,bytes([0x31+i]))
  self.nv={i:bytes([0x41,raw,100,50,0x5a])for i in range(6)}
  self.put(RAM,self.nv[mode]);self.put(0xa010183c,b'\x20')
 def put(self,addr,data):
  for i,b in enumerate(data):self.mem[(addr+i)&0xffffffff]=b
 def read(self,addr,width=1):
  bs=[]
  for i in range(width):
   a=(addr+i)&0xffffffff
   bs.append(self.image[a-BASE]if BASE<=a<BASE+len(self.image)else self.mem.get(a,0))
  return int.from_bytes(bytes(bs),'little')
 def record(self):return self.read(RAM,5).to_bytes(5,'little')
 def service(self,pc):
  r=self.r
  if pc==BASE+0xdc30:r['v0']=int(self.hdr)
  elif pc==BASE+0x26d58:r['v0']=self.mode
  elif pc==BASE+0xdad3c:
   assert r['a0']==self.sel_a0;self.gate_calls.append('s');r['v0']=self.sval
  elif pc==BASE+0xaeb64:
   assert r['a0']==self.sel_a0;a=r['a0'];self.gate_calls.append('idx');r['v0']=0 if a==255 or a&2 else a&3
  elif pc==BASE+0xdae88:
   a=self.sel_a0;idx=0 if a==255 or a&2 else a&3
   assert r['a0']==0x31+idx,(r['a0'],idx);self.gate_calls.append('f2');r['v0']=self.f2
  elif pc==BASE+0xdf08:r['v0']=(self.read(RAM+1)>>3)&3
  elif pc==BASE+0xde5cc:
   assert r['a1']==5 and r['a2']==RAM
   mode=(r['a0']-148)//5;assert r['a0']==148+5*mode
   if self.read_ok:self.put(RAM,self.nv[mode])
   r['v0']=int(self.read_ok);self.services.append(('read',mode))
  elif pc==BASE+0x7b24:
   mode=r['a0'];assert 0<=mode<6
   if self.write_ok:self.nv[mode]=self.record()
   self.writes.append(mode);r['v0']=int(self.write_ok)
  elif pc==BASE+0xdc258:self.services.append(('bracket',r['a0'],r['a1']))
  elif pc==BASE+0xd5f24:r['v0']=3
  elif pc==BASE+0xda470:self.services.append(('refresh',r['a0']))
  elif pc==BASE+0xdfdb4:self.events.append((r['a0'],r['a1']))
  elif pc==BASE+0x14c78:
   assert r['a0']==24 and 0<=r['a1']<7
   r['v0']=self.read(BASE+0xe9548+r['a1'])
  elif pc==BASE+0x2604:
   data=self.read(r['a1'],r['a2']).to_bytes(r['a2'],'little');self.put(r['a0'],data);r['v0']=r['a0']
  elif pc in (BASE+0xcb2b0,BASE+0xd2238):r['v0']=0
  elif self.navigation and pc==BASE+0x15268 and r['a0']!=198:r['v0']=0
  elif self.navigation and pc==BASE+0x177dc:r['v0']=0
  else:return False
  return True
 def run(self,start,args=(),stop_at=None):
  self.r['ra']=STOP|1
  for i,value in enumerate(args):self.r[f'a{i}']=value
  pc=start&~1
  for count in range(2000):
   if pc==STOP or pc==stop_at:return count
   if self.service(pc):pc=self.r['ra']&~1;continue
   assert pc in self.code,f'No decoded instruction at {pc:#x}'
   nxt,width,op=self.step(pc)
   if self.delay!='none' and self.active(pc):
    branch=op=='b' or (op in ('bteqz','btnez','beqz','bnez') and nxt!=pc+width)
    if op in ('jal','jr') or (self.delay=='jump+branch' and branch):
     spc=pc+width;assert spc in self.code
     sw=self.code[spc][0];assert self.code[spc][1] not in ('jal','jr','b','bteqz','btnez','beqz','bnez'),f'control op in slot at {spc:#x}'
     self.step(spc)
     if op=='jal':self.r['ra']=(spc+sw)|1
   pc=nxt
  raise AssertionError('Instruction limit exceeded')
 def active(self,pc):return pc>=0x86131000 or any(0x86000000+o<=pc<0x86000000+o+n for o,n in SITES)
 def step(self,pc):
   r=self.r
   width,op,arg=self.code[pc];p=arg.split(',');nxt=pc+width
   def val(x):return r[x]if x in r else int(x,0)
   def target():return int(re.search(r'0x[0-9a-f]+',arg)[0],16)&~1
   m=re.fullmatch(r'(\w+),(-?\d+)\((\w+)\)',arg)
   if op=='li':r[p[0]]=int(p[1],0)
   elif op=='lui':r[p[0]]=int(p[1],0)<<16
   elif op=='move':r[p[0]]=val(p[1])
   elif op=='addiu':r[p[0]]=val(p[0]if len(p)==2 else p[1])+int(p[-1],0)
   elif op in ('addu','subu','and','or','xor'):
    x,y=(val(p[0]),val(p[1]))if len(p)==2 else(val(p[1]),val(p[2]))
    r[p[0]]={'addu':lambda:x+y,'subu':lambda:x-y,'and':lambda:x&y,'or':lambda:x|y,'xor':lambda:x^y}[op]()
   elif op in ('sll','srl'):
    x=val(p[0]if len(p)==2 else p[1]);n=int(p[-1],0)
    r[p[0]]=x<<n if op=='sll' else x>>n
   elif op=='neg':r[p[0]]=-val(p[-1])
   elif op=='not':r[p[0]]=~val(p[-1])
   elif op=='cmpi':r['t8']=val(p[0])^int(p[1],0)
   elif op=='cmp':r['t8']=val(p[0])^val(p[1])
   elif op=='sltiu':r['t8']=int(val(p[0])<int(p[1],0))
   elif op=='sltu':r['t8']=int(val(p[0])<val(p[1]))
   elif op in ('lw','lhu','lbu','sw','sh','sb'):
    assert m,arg
    addr=(r[m[3]]+int(m[2]))&0xffffffff;size={'lw':4,'sw':4,'lhu':2,'sh':2,'lbu':1,'sb':1}[op]
    if op[0]=='l':r[m[1]]=self.read(addr,size)
    else:self.put(addr,(r[m[1]]&((1<<(size*8))-1)).to_bytes(size,'little'))
   elif op=='jal':r['ra']=nxt|1;nxt=target()
   elif op=='jr':
    assert val(p[0])&1,f'JR without MIPS16 ISA bit at {pc:#x}'
    nxt=val(p[0])&~1
   elif op=='b':nxt=target()
   elif op in ('bteqz','btnez'):
    if (r['t8']==0)==(op=='bteqz'):nxt=target()
   elif op in ('beqz','bnez'):
    if (val(p[0])==0)==(op=='beqz'):nxt=target()
   elif op=='nop':pass
   else:raise AssertionError(f'Unsupported executed instruction at {pc:#x}: {op} {arg}')
   for k in r:r[k]&=0xffffffff
   return nxt,width,op


def intact(m):assert (m.r['sp'],m.r['s0'],m.r['s1'])==(SP,0x1357,0x2468)
def lvl(raw):return 0 if raw&0x60==0 else 1 if raw&0x60==0x20 else 2
counts={}
# Execute through actual entry trampolines and stock epilogues.
for raw in range(256):
 m=Machine(raw=raw);m.run(BASE+0xf900,(198,));intact(m)
 assert m.read(DESC)==1 and m.read(DESC+4,2)==2 and m.read(DESC+6,2)==0
 assert m.read(DESC+8)==1 and m.read(DESC+10,2)==198 and m.read(DESC+12,2)==399
 assert m.read(DESC+2,2)==lvl(raw)
counts['descriptor']=256
for mode in range(6):
 for hdr in (False,True):
  for apl in range(4):
   m=Machine(mode=mode,hdr=hdr,raw=apl<<3);m.run(BASE+0x15268,(198,));intact(m)
   assert m.r['v0']==int(not(hdr and mode==4))
counts['availability']=48
tables=[symbols['hn_medium0'],symbols['hn_medium1'],symbols['hn_high0'],symbols['hn_high1']]
n_sel=0
for raw in range(256):
 for mode in range(6):
  for hdr in (False,True):
   for variant in (0,1):
    for a0 in (0x20,255):
     m=Machine(mode=mode,hdr=hdr,raw=raw);m.sel_a0=a0;m.run(BASE+0xd6238,(a0,variant));intact(m)
     l=lvl(raw) if hdr and mode==4 else 0
     expected=tables[2*(l-1)+variant] if l else int.from_bytes(stock[0x12c374+4*variant:0x12c378+4*variant],'little')
     assert m.r['v0']==expected,(raw,mode,hdr,variant,hex(m.r['v0']),hex(expected))
     assert m.gate_calls==[]
     n_sel+=1
counts['selector']=n_sel
# APL gate: stock type-5 builder calls df08() at 0xe3ea4 and needs 2; hooked call says 2 only when Medium/High is active.
site=code[BASE+0xe3ea4]
assert site[1]=='jal' and int(re.search(r'0x[0-9a-f]+',site[2])[0],16)&~1==symbols['apl_override'],site
assert code[BASE+0xe3ea8][1]=='cmpi' and code[BASE+0xe3eaa][1]=='btnez'
assert candidate[0xe3ea8:0xe3eac]==stock[0xe3ea8:0xe3eac]
n_apl=0
for raw in range(256):
 for mode in range(6):
  for hdr in (False,True):
   m=Machine(mode=mode,hdr=hdr,raw=raw);m.run(BASE+0xe3ea4,(),BASE+0xe3eaa);intact(m)
   active=hdr and mode==4 and lvl(raw)>0
   assert m.r['v0']==(2 if active else (raw>>3)&3),(raw,mode,hdr,m.r['v0'])
   assert (m.r['t8']==0)==(m.r['v0']==2)
   n_apl+=1
counts['apl_gate']=n_apl
for raw in range(256):
 for mode in range(6):
  for success in (False,True):
   m=Machine(mode=(mode+1)%6,raw=raw,read_ok=success)
   before=m.record();m.run(BASE+0x7694,(mode,));intact(m)
   expected=bytearray(before);dirty=False
   if mode==4:
    if success and raw&0x80:expected[1]=raw&0x1f;dirty=True
    elif not success:expected[1]=raw&0x1f
   assert m.record()==expected and m.r['v0']==int(success),(mode,raw,success,m.record())
   assert m.writes==([mode]if dirty else []),m.writes
counts['load_legacy_cleanup']=256*6*2
for raw in range(256):
 for mode in range(6):
  for pending in (0,1,2,3,255):
   m=Machine(mode=mode,raw=raw);m.put(DESC+2,pending.to_bytes(2,'little'))
   m.run(BASE+0x11324,(198,));intact(m)
   expected=raw
   if mode==4 and pending<3:expected=(raw&0x1f)|(pending<<5)
   assert m.read(RAM+1)==expected
   changed=expected!=raw
   assert m.events==[]
   assert m.writes==([4]if changed else [])
   if changed:assert m.nv[4][1]==expected
   assert m.services==([('bracket',32,1),('bracket',33,1),('refresh',3),('bracket',32,0),('bracket',33,0)]if changed else [])
counts['live_commit']=256*6*5
for raw in range(256):
 for pending in (0,1,2):
  m=Machine(raw=raw,write_ok=False);before=m.record();durable=m.nv.copy()
  m.put(DESC+2,pending.to_bytes(2,'little'));m.run(BASE+0x11324,(198,));intact(m)
  assert m.record()==before and m.nv==durable and not m.events and not m.services
  if m.writes:assert m.read(DESC+2,2)==lvl(raw)
counts['failed_commit_rollback']=768
for raw in range(256):
 m=Machine(raw=raw,write_ok=False);durable=m.nv.copy();m.run(BASE+0x7694,(4,));intact(m)
 assert m.r['v0']==1 and m.nv==durable
 if raw&0x80:assert m.read(RAM+1)==raw&0x1f and m.writes==[4]
counts['failed_cleanup_write']=256
for pending in (1,2):
 m=Machine(raw=0x10);m.put(DESC+2,pending.to_bytes(2,'little'))
 m.run(BASE+0x11324,(198,));intact(m);saved=m.nv[4]
 # Simulate the next mode replacing RAM, then returning to Peak1000: the preference must survive.
 m.mode=2;m.run(BASE+0x7694,(2,));m.mode=4;m.run(BASE+0x7694,(4,));intact(m)
 assert m.record()==saved and lvl(m.read(RAM+1))==pending
counts['immediate_mode_switch_persistence']=2
for row in range(7):
 m=Machine();m.run(BASE+0x20de8,(429,row));intact(m)
 expected=[0x1247e8,0x124d00,0x12792c,0x1249cc,0x125348,symbols['hypernits_label']-BASE,0x129d7c][row]+BASE
 assert m.r['v0']==expected,(row,hex(m.r['v0']),hex(expected))
counts['row_labels']=7
def text(m,p):
 out=bytearray()
 while True:
  b=m.read(p+len(out))
  if b==0xff:return bytes(out)
  out.append(b)
for v,want in ((0,'2d4040'),(1,'2a2b3f3e434f4700'),(2,'25434142'),(3,'2d4040'),(255,'2d4040')):
 m=Machine();m.run(BASE+0x20de8,(399,v));intact(m)
 assert text(m,m.r['v0']).hex()==want,(v,text(m,m.r['v0']).hex())
counts['value_strings']=5
for group in range(256+256):
 if group==399:continue
 m=Machine();m.run(BASE+0x20de8,(group,1),BASE+0x20df4)
 assert m.r['a0']==group and m.r['v1']==(group-389)&0xffffffff and m.r['v0']==group and m.r['sp']==SP-24
 assert m.read(SP-24+20,4)==STOP|1 and m.read(SP-24+16,4)==0x1357
counts['string_lookup_passthrough']=511
for mode in range(6):
 m=Machine(mode=mode,raw=0xb0);m.run(BASE+0x7940,(mode,));intact(m)
 assert m.record()==stock[0x10e9ec+5*mode:0x10e9f1+5*mode] and m.writes==[mode]
counts['reset']=6
# Original ID198 is unassigned in the key native dispatchers.
m=Machine(stock,original_code);m.run(BASE+0xf900,(198,));assert m.read(DESC+10,2)==0;intact(m)
m=Machine(stock,original_code);m.run(BASE+0x11324,(198,));assert not m.events;intact(m)
m=Machine(stock,original_code);m.run(BASE+0x11ac0,(198,));assert not m.events;intact(m)
counts['original_id198_fallback']=3
for item in range(197):
 m=Machine();m.run(BASE+0xf900,(item,),BASE+0xf90c)
 assert m.r['v0']==0xa0100000 and m.r['sp']==SP-40 and m.read(SP-40+32,4)==0x2468 and m.read(SP-40+28,4)==0x1357
 m=Machine();m.run(BASE+0x15268,(item,),BASE+0x15272)
 assert m.r['a0']==item and m.r['s0']==item and m.r['a2']==30 and m.read(SP-56+48,4)==0x1357
counts['existing_descriptor_availability_passthrough']=197*2
for item in range(256):
 if item==198:continue
 target=BASE+(0x1132e if item<126 else 0x114a2)
 m=Machine();m.run(BASE+0x11324,(item,),target)
 assert m.r['a0']==item and m.r['sp']==SP-24 and m.read(SP-24+20,4)==STOP|1
 assert not m.writes and not m.events
counts['existing_commit_dispatch_passthrough']=255
for mode in (2,4):
 for row in range(7):
  for direction in (3,4):
   m=Machine(mode=mode,navigation=True);m.put(0xa010184c,(24).to_bytes(2,'little'));m.put(0xa010185c,bytes([row]))
   m.run(BASE+0x1623c,(direction,7));intact(m)
   delta=-1 if direction==3 else 1;expected=(row+delta)%7
   if mode!=4 and expected==5:expected=(expected+delta)%7
   assert m.read(0xa010185c)==expected,(mode,row,direction,m.read(0xa010185c),expected)
counts['seven_row_navigation_native']=28
report={'status':'PASS: assembled-hook semantic harness; hardware services stubbed',
 'image_sha256':hashlib.sha256(candidate).hexdigest(),'cases':counts,'total_cases':sum(counts.values()),
 'limitations':__doc__}
(OUT/f'semantic_checks_{DELAY.replace("+","_")}.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
