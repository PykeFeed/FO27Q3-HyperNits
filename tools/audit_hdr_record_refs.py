"""Conservative straight-line constant propagation for HDR-record references.

Branch boundaries discard register knowledge; calls discard caller-saved values.
This intentionally misses references requiring inter-block/stack/alias analysis.
It cannot prove a bit unused. No firmware writes.
"""
import json,re
from trace_mips import ROOT,load

rows=load('FO27Q3'); constants={}; refs=[]
no_write={'sw','sb','sh','cmp','cmpi','slt','sltu','slti','sltiu','div','divu','mult','multu','nop'}
control={'b','beqz','bnez','btnez','bteqz','jr','j','jalx'}
for r in rows:
 if r['address']>=0x860e7ff8:break
 op=r['op'];parts=r['args'].split(',');dest=parts[0]
 m=re.fullmatch(r'(\w+),(-?\d+)\((\w+)\)',r['args'])
 if m and m[3] in constants:
  addr=(constants[m[3]]+int(m[2]))&0xffffffff
  if 0xa0101a74<=addr<0xa0101a79:
   refs.append({'file_offset':hex(r['address']-0x86000000),'ram':hex(addr),
      'kind':'memory','instruction':r['line']})
 value=None
 try:
  if op=='lui':value=int(parts[1],0)<<16
  elif op=='li':value=int(parts[1],0)
  elif op=='move':value=constants.get(parts[1])
  elif op=='addiu':
   source=dest if len(parts)==2 else parts[1]
   if source in constants:value=constants[source]+int(parts[-1],0)
  elif op=='addu':
   lhs,rhs=(dest,parts[1])if len(parts)==2 else(parts[1],parts[2])
   if lhs in constants and rhs in constants:value=constants[lhs]+constants[rhs]
 except (ValueError,IndexError):pass
 if op=='jal':
  for reg in ('a0','a1','a2','a3'):
   if 0xa0101a74<=constants.get(reg,0)<0xa0101a79:
    refs.append({'file_offset':hex(r['address']-0x86000000),'ram':hex(constants[reg]),
      'kind':'call_argument','register':reg,'instruction':r['line']})
  for reg in ('v0','v1','a0','a1','a2','a3','t8'):constants.pop(reg,None)
 elif op in control:constants.clear()
 elif op not in no_write:
  constants.pop(dest,None)
  if value is not None:constants[dest]=value&0xffffffff

report={'method':__doc__,'references':refs}
(ROOT/'research/FO27Q3.hdr_record_refs.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'{len(refs)} resolved references. Incomplete alias audit; no free-bit claim.')
for r in refs:print(r['file_offset'],r['ram'],r['kind'],r.get('register',''),r['instruction'].split(':',1)[1])
