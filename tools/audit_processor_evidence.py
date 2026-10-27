"""Corroborate execution assumptions against native code; no hardware proof."""
import json
from trace_mips import ROOT,load
rows=load('FO27Q3');native={r['address']:r for r in rows if r['address']<0x860e7ff8}
pairs=[]
for a,r in native.items():
 if r['op']=='jal' and (n:=native.get(a+4))and n['op']=='jal':
  pairs.append({'first':r['line'],'next':n['line']})
examples=[p for p in pairs if any(f'8600{x}'in p['first']for x in ['95e8','9610','9630'])]
# Explicit known reset-path example, reachable through already-traced reset code.
assert native[0x860095e8]['op']=='jal'and native[0x860095ec]['op']=='jal'
report={'status':'Static corroboration only; target core identity/execution not measured',
 'native_adjacent_direct_call_pairs':len(pairs),'reset_path_example':
   [native[0x860095e8]['line'],native[0x860095ec]['line']],
 'other_examples':pairs[:20],
 'interpretation':'Stock direct-call pairs are incompatible with treating the second jump as an ordinary legal delayed jump slot. This supports a target-specific execution variant or decoder interpretation; it does not identify the CPU.',
 'external_primary_authored_source':{
  'url':'https://www.scribd.com/document/919421602/lx5180-1-9',
  'section':'Lexra LX5180 Data Sheet release1.9 section4.4, p38',
  'finding':'Conditional MIPS16 branches have no delay slot, but JAL/JALX/JR/JALR retain one. The section heading alone cannot justify delay-free jumps.',
  'limitation':'No established mapping from RTD2738 to this core; do not use it as a target specification.'},
 'validation_still_needed':['Authoritative target core/mode documentation or observed hardware trace',
  'Confirm return-link semantics and instruction-mode selection','Confirm executable mapping of added arena']}
(ROOT/'research/processor_execution_evidence.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['status','native_adjacent_direct_call_pairs','reset_path_example']},indent=2))
