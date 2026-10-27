"""Static PE import/export/function analysis. Never loads or executes DLLs."""
from pathlib import Path
import sys,json,argparse
sys.path.insert(0,str(Path(__file__).resolve().parent/'re_deps'))
import pefile,capstone
from capstone.x86 import X86_OP_MEM,X86_OP_IMM,X86_REG_RIP
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('name');p.add_argument('--start',type=lambda x:int(x,0));p.add_argument('--end',type=lambda x:int(x,0));args=p.parse_args()
path=ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD'/args.name
pe=pefile.PE(str(path));base=pe.OPTIONAL_HEADER.ImageBase
imports={}
for group in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):
 for i in group.imports:imports[i.address]=group.dll.decode()+'!'+(i.name.decode()if i.name else '#'+str(i.ordinal))
exports={base+i.address:i.name.decode()if i.name else '#'+str(i.ordinal)for i in getattr(pe,'DIRECTORY_ENTRY_EXPORT',type('E',(),{'symbols':[]})).symbols}
functions=[(e.struct.BeginAddress,e.struct.EndAddress)for e in getattr(pe,'DIRECTORY_ENTRY_EXCEPTION',[])]
summary={'file':str(path.relative_to(ROOT)),'image_base':hex(base),'exports':{hex(k):v for k,v in exports.items()},
 'imports':{hex(k):v for k,v in imports.items()},'runtime_functions':[(hex(a),hex(b))for a,b in functions]}
(ROOT/'research'/f'{args.name}.pe_map.json').write_text(json.dumps(summary,indent=2)+'\n')
if args.start is None:
 print(json.dumps({'base':hex(base),'exports':summary['exports'],'runtime_functions':len(functions)},indent=2));raise SystemExit()
start=args.start;end=args.end
if end is None:end=next((b for a,b in functions if a<=start<b),start+0x200)
engine=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);engine.detail=True
data=pe.get_data(start,end-start);lines=[]
for i in engine.disasm(data,base+start):
 notes=[]
 for o in i.operands:
  if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP:
   dest=i.address+i.size+o.mem.disp
   if dest in imports:notes.append(imports[dest])
   else:notes.append('RIP->'+hex(dest-base))
  elif o.type==X86_OP_IMM and o.imm in exports:notes.append(exports[o.imm])
 lines.append(f'{i.address-base:08x}: {i.mnemonic:8} {i.op_str}'+(' ; '+'; '.join(notes)if notes else ''))
text='\n'.join(lines)+'\n'
(ROOT/'research'/f'{args.name}.{start:x}-{end:x}.asm').write_text(text)
print(text)
