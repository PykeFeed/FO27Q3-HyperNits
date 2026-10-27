"""Compare traced table loaders, retaining register/branch semantics; no firmware writes."""
import json,re
from trace_mips import load,ROOT

def routine(name,start,end):
    rows=[r for r in load(name) if 0x86000000+start <= r['address'] < 0x86000000+end]
    normalized=[]
    calls=[]
    for r in rows:
        args=r['args']
        if r['op']=='jal':
            calls.append({'relative_offset':hex(r['address']-0x86000000-start),'target':args})
            args='<relocated call>'
        elif r['op'] in ('b','bnez','beqz','bteqz','btnez'):
            args=re.sub(r'0x[0-9a-f]+',lambda m:hex(int(m[0],16)-0x86000000-start),args)
        normalized.append((r['address']-0x86000000-start,r['op'],args))
    return normalized,calls

a,ac=routine('MO27Q2A',0x2b3d0,0x2b55c)
b,bc=routine('FO27Q3',0x2f700,0x2f88c)
report={'comparison':'Instruction offsets/opcodes/operands identical after normalizing calls and local branch addresses',
        'equal':a==b,'instruction_count':[len(a),len(b)],
        'donor_calls':ac,'target_calls':bc,
        'limitations':'Static comparison only. Called routines are not verified equivalent by this check; no hardware test.',
        'loader_contract':{'payload_bytes':195,'separate_bytes':[195,196],
            'logical_register_offsets':[2464,2466,2467],
            'physical_register_formula':'0xa0000000 + 4*(region_base + logical_offset)',
            'segment_scaling':'unverified'}}
(ROOT/'research/hdr_loader_comparison.json').write_text(json.dumps(report,indent=2))
assert a==b, 'Loader instructions differ; inspect report and disassembly'
assert len(a)>100, 'Incomplete disassembly'
print(f'PASS: {len(a)} loader instructions match after relocation normalization; callees not verified.')
