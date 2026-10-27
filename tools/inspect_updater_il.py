"""Decode managed updater IL and metadata without executing the updater."""
from pathlib import Path
import sys,json
sys.path.insert(0,str(Path(__file__).resolve().parent/'re_deps'))
import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.clr.token import Token,StringToken
ROOT=Path(__file__).resolve().parents[1]
p=dnfile.dnPE(str(ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/UpdFW_RTK.exe'))
tables={0x04:p.net.mdtables.Field,0x06:p.net.mdtables.MethodDef,0x0a:p.net.mdtables.MemberRef,0x01:p.net.mdtables.TypeRef,0x02:p.net.mdtables.TypeDef}
def resolve(operand):
 if isinstance(operand,StringToken):
  try:return repr(str(p.net.user_strings.get(operand.value&0xffffff)))
  except Exception:return str(operand)
 if isinstance(operand,Token):
  table=tables.get(operand.value>>24);index=(operand.value&0xffffff)-1
  if table and 0<=index<len(table.rows):
   row=table.rows[index]
   return f'{operand.value:#010x} '+str(getattr(row,'Name',getattr(row,'TypeName','unknown')))
 return str(operand)if operand is not None else ''
lines=[];calls=[]
for index,method in enumerate(p.net.mdtables.MethodDef.rows,1):
 if not method.Rva:continue
 lines.append(f'\nMETHOD 0x0600{index:04x} {method.Name} RVA {method.Rva:#x}')
 body=read_method_body_from_bytes(p.get_data(method.Rva,0x10000))
 for ins in body.instructions:
  operand=resolve(ins.operand);lines.append(f'{ins.offset:04x}: {str(ins.opcode):16} {operand}')
  if 'fnNewFlashBIOS' in operand:calls.append({'caller':str(method.Name),'rva':hex(method.Rva),'instruction_offset':hex(ins.offset),'target':operand})
(ROOT/'research/UpdFW_RTK.il.txt').write_text('\n'.join(lines)+'\n')
imports=[{'name':str(m.ImportName),'dll':str(m.ImportScope.row.Name),'method_index':m.MemberForwarded.row_index}for m in p.net.mdtables.ImplMap.rows]
(ROOT/'research/UpdFW_RTK.managed.json').write_text(json.dumps({'pinvoke':imports,'flash_calls':calls},indent=2)+'\n')
print(json.dumps({'methods_with_bodies':sum(bool(m.Rva)for m in p.net.mdtables.MethodDef.rows),'flash_calls':calls},indent=2))
