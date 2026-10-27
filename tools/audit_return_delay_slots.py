"""Static test #2 for delay-slot semantics: what instruction follows `jr ra` / `jal` in stock F05?

If the core had a branch/jump delay slot, the instruction after `jr ra` would be the slot and
could not be a branch, a jump, a call, a stack-frame allocation (`addiu sp,-N`) or a flag-setting
compare used only by a following branch. This counts how often such "impossible slot" cases occur
inside the native code range (<0x860e7ff8). Heuristic: no CFG, data can decode as code.
"""
import re,json,collections
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
rows=[]
for l in (ROOT/'research/FO27Q3.mips16.asm').read_text().splitlines():
    m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4} ?)+)\s+([\w.]+)\s*(.*)',l)
    if m and int(m[1],16)<0x860e7ff8:rows.append((int(m[1],16),m[3],m[4].strip()))
BR={'b','beqz','bnez','bteqz','btnez'};J={'jal','jalx','jr','jalr'}
res=collections.Counter();ex=collections.defaultdict(list)
for i,(a,o,ar) in enumerate(rows[:-1]):
    if o=='jr' and ar=='ra':
        n=rows[i+1];res['jr_ra_total']+=1
        k=None
        if n[1] in BR:k='branch_after_jr_ra'
        elif n[1] in J:k='jump_or_call_after_jr_ra'
        elif n[1]=='addiu' and n[2].startswith('sp,-'):k='stack_alloc_after_jr_ra'
        elif n[1] in('cmpi','sltiu','cmp','slti','sltu','slt'):k='compare_after_jr_ra'
        if k:res[k]+=1;ex[k].append((hex(a),n[1],n[2]))
res['impossible_slot_total']=sum(res[k] for k in('branch_after_jr_ra','jump_or_call_after_jr_ra','stack_alloc_after_jr_ra'))
rep={'status':'Static heuristic; strongly favors NO delay slot after JR RA in stock code; not hardware proof',**res,
 'examples':{k:v[:5] for k,v in ex.items()}}
(ROOT/'research/return_delay_slot_evidence.json').write_text(json.dumps(rep,indent=2)+'\n');print(json.dumps(rep,indent=2))
