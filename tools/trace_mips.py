"""Index GNU MIPS16 disassembly and split-address references. Read-only.

Linear disassembly includes DATA. Results require control-flow validation.
"""
from pathlib import Path
import re,json,argparse
ROOT=Path(__file__).resolve().parents[1]

def load(name):
    rows=[]
    for line in (ROOT/'research'/f'{name}.mips16.asm').read_text().splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4} ?)+)\s+([\w.]+)\s*(.*)',line)
        if m: rows.append(dict(address=int(m[1],16),raw=m[2].strip(),op=m[3],args=m[4].strip(),line=line.strip()))
    return rows

def split_refs(rows):
    refs=[]
    for i,r in enumerate(rows):
        if r['op']!='lui':continue
        m=re.fullmatch(r'(\w+),0x([0-9a-f]+)',r['args'])
        if not m:continue
        reg=m[1]; high=int(m[2],16)<<16
        for n in rows[i+1:i+9]:
            if n['op']=='addiu' and (m2:=re.fullmatch(reg+r',(-?\d+)',n['args'])):
                refs.append(dict(address=hex(r['address']),end=hex(n['address']),reg=reg,value=hex((high+int(m2[1]))&0xffffffff)))
                break
            # Only allow non-writing intervening instructions for this register.
            if n['op'] in ('jal','jalx','jr','j','b') or (n['args'].split(',')[0]==reg and n['op'] not in ('sw','sb','sh','cmpi','cmp','slti','sltiu')):break
    return refs

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('image',choices=['FO27Q3','MO27Q2A']);p.add_argument('--start',type=lambda s:int(s,0));p.add_argument('--end',type=lambda s:int(s,0));p.add_argument('--value',type=lambda s:int(s,0));args=p.parse_args()
 rows=load(args.image)
 if args.start is not None:
  lo=args.start+(0x86000000 if args.start<0x80000000 else 0); hi=args.end+(0x86000000 if args.end<0x80000000 else 0)
  print('\n'.join(r['line'] for r in rows if lo<=r['address']<hi))
 else:
  refs=split_refs(rows);(ROOT/'research'/f'{args.image}.split_refs.json').write_text(json.dumps(refs,indent=2))
  if args.value is not None:print(json.dumps([r for r in refs if int(r['value'],16)==args.value],indent=2))
  else:print(f'{len(rows)} instructions/data decodes; {len(refs)} split-address candidates')
