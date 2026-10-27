"""Extend candidate harness through native NVRAM writer/page splitter.

The native 0x7b24/0xde644/0xde408 instructions execute in the semantic harness.
Only logical copying and low-level bus write/ready services are stubbed. No I/O.
"""
import json,runpy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ns=runpy.run_path(str(ROOT/'tools/verify_hypernits_candidate.py'))
Machine=ns['Machine'];BASE=ns['BASE'];RAM=ns['RAM'];intact=ns['intact']
class NativeStorage(Machine):
 def __init__(self,*args,fail_transfer=False,ready=True,**kwargs):
  super().__init__(*args,**kwargs)
  self.storage=bytearray((i*37+11)&255 for i in range(2048));self.transfers=[]
  self.fail_transfer=fail_transfer;self.ready=ready;self.polls=0
 def service(self,pc):
  r=self.r
  if pc==BASE+0x7b24:return False
  if pc==BASE+0xcb178:
   self.put(r['a0'],self.read(r['a1'],r['a2']).to_bytes(r['a2'],'little'));r['v0']=r['a0'];return True
  if pc==BASE+0x9e970:
   addr=r['a2'];count=r['a3'];ptr=self.read(r['sp']+16,4);bus=self.read(r['sp']+20,1)
   assert r['a0']==0xa0 and r['a1']==2 and bus==25
   assert count>0 and addr//32==(addr+count-1)//32
   data=self.read(ptr,count).to_bytes(count,'little')
   self.transfers.append(dict(address=addr,length=count,data=data.hex(' ')))
   if not self.fail_transfer:self.storage[addr:addr+count]=data
   r['v0']=int(not self.fail_transfer);return True
  if pc==BASE+0x9e98c:self.polls+=1;r['v0']=int(self.ready);return True
  if pc==0x850002fc:return True # Delay only; no real timing.
  return super().service(pc)

results=[]
for mode in range(6):
 for fail in (False,True):
  m=NativeStorage(mode=mode,raw=0xb0,fail_transfer=fail);before=bytes(m.storage)
  m.run(BASE+0x7b24,(mode,));intact(m)
  expected=bytearray(before)
  if not fail:expected[148+5*mode:153+5*mode]=m.record()
  assert m.storage==expected and m.r['v0']==int(not fail)
  assert sum(t['length']for t in m.transfers)==(m.transfers[0]['length']if fail else 5)
  results.append({'mode':mode,'failure':fail,'transfers':m.transfers,'return':m.r['v0']})
# A bus accepts data but never acknowledges readiness: native writer returns0.
m=NativeStorage(mode=4,raw=0xb0,ready=False);m.run(BASE+0x7b24,(4,));intact(m)
assert m.r['v0']==0 and len(m.transfers)==1 and m.polls==50
timeout_polls=m.polls
# New toggle rollback must still work when using actual native write wrappers.
for pending in (0,1):
 for fail in (False,True):
  m=NativeStorage(raw=0x90 if pending==0 else 0xb0,fail_transfer=fail)
  old=m.record();m.put(ns['DESC']+2,pending.to_bytes(2,'little'))
  m.run(BASE+0x11324,(198,));intact(m)
  assert len(m.transfers)==1 and m.transfers[0]['address']==168 and m.transfers[0]['length']==5
  if fail:assert m.record()==old
  else:assert m.storage[168:173]==m.record()and bool(m.read(RAM+1)&32)==(pending==0)
report={'status':'PASS: native writer/page splitter with bus stubs','cases':17,
 'candidate_sha256':ns['report']['image_sha256'],'writer_results':results,
 'peak1000_write':{'logical_address':168,'bytes':5,'page_bytes':32,'single_transfer':True},
 'ready_timeout_polls':timeout_polls,
 'limitations':['Semantic instruction engine assumes delay-free target execution',
 'No real EEPROM bus/timing/atomicity validation','Ready failure can follow a physically accepted write; RAM rollback cannot undo that durable write']}
(ROOT/'research/native_storage_checks.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['status','cases','peak1000_write']},indent=2))
