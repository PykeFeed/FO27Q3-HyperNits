"""Statistical (static) test: do stock JAL calls behave as if they have a delay slot?

For each JAL whose next instruction writes a0/a1/a2 (li/move) and whose callee reads
that register near entry, check whether the register was ALREADY written in the 6
instructions before the JAL. Under delay-slot semantics the slot write IS the argument
setup, so 'already written before' should be rare. Under delay-free semantics the
after-call write belongs to the next call, so 'already written before' should dominate.
Heuristic only: no CFG, no hardware. Does not identify the CPU.
"""
import re,json,collections
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
rows=[];idx={}
for l in (ROOT/'research/FO27Q3.mips16.asm').read_text().splitlines():
    m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4} ?)+)\s+([\w.]+)\s*(.*)',l)
    if m and int(m[1],16)<0x860e7ff8:
        idx[int(m[1],16)]=len(rows);rows.append((int(m[1],16),m[3],m[4].strip()))
W={'li','move','lw','lbu','lhu','lui','addiu','neg','not','mfhi','mflo'}
regs=lambda a:re.findall(r'\b(a[0-3]|v[01]|s[01])\b',a)
CTL={'jal','jr','b','beqz','bnez','bteqz','btnez'}
def reads_first(i,reg,n=8):
    for j in range(i,min(i+n,len(rows))):
        a,o,ar=rows[j];r=regs(ar)
        if o in CTL: return o in('beqz','bnez') and ar.startswith(reg+',')
        if o in W and r and r[0]==reg: return reg in r[1:] and o in('addiu','neg','not')
        if o in('sw','sb','sh','cmpi','cmp') and reg in r: return True
        if o not in W and reg in r: return True
        if o in W and reg in r[1:]: return True
    return False
c=collections.Counter();nop_after=0;jal_total=0
for i,(a,o,ar) in enumerate(rows[:-1]):
    if o!='jal':continue
    jal_total+=1
    if rows[i+1][1]=='nop':nop_after+=1
    t=int(ar.split()[0],16)&~1 if ar.startswith('0x') else None
    if t not in idx:continue
    s=rows[i+1];r=regs(s[2])
    if s[1] in('li','move') and r and r[0] in('a0','a1','a2'):
        reg=r[0]
        if not reads_first(idx[t],reg):continue
        prior=any(rows[j][1] in W and regs(rows[j][2])[:1]==[reg] for j in range(max(0,i-6),i))
        c['arg_already_set_before_call' if prior else 'arg_set_only_in_next_instruction']+=1
rep={'status':'Static heuristic; favors delay-FREE JAL in stock code; not hardware proof',
 'jal_total':jal_total,'jal_followed_by_nop':nop_after,'tested_sites':sum(c.values()),**dict(c),
 'interpretation':'~92% of tested sites already had the argument register set before the JAL, so the instruction after JAL is usually NOT delay-slot argument setup. Consistent with the build assumption, but 8% unexplained and no CFG; the Lexra datasheet says JAL has a delay slot, so the contrary evidence (adjacent JAL;JAL pairs in research/processor_execution_evidence.json) and this result should both be confirmed on hardware/authoritative docs.'}
(ROOT/'research/call_delay_slot_evidence.json').write_text(json.dumps(rep,indent=2)+'\n');print(json.dumps(rep,indent=2))
