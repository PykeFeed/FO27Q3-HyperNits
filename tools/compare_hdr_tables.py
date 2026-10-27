"""Extract observed 200-byte LUT slots; 12-bit unpacking remains a format hypothesis."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[1]
donor=(ROOT/'extracted/MO27Q2A_F03/FWUPD/F03.bin').read_bytes()
target=(ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/F05.bin').read_bytes()
out=[]
for name,data,table,count in [('MO27Q2A',donor,0x1333a4,16),('FO27Q3',target,0x12c354,10)]:
 for index in range(count):
  offset=int.from_bytes(data[table+index*4:table+index*4+4],'little')-0x86000000
  raw=data[offset:offset+200]
  samples=[]
  for n in range(0,195,3):
   v=int.from_bytes(raw[n:n+3],'big');samples.extend([v>>12,v&0xfff])
  row=dict(image=name,index=index,offset=hex(offset),length=200,sha256=hashlib.sha256(raw).hexdigest(),
           raw=raw.hex(' '),hypothesis_packed12=samples[:129],trailing_halfword_sample=samples[129],
           trailing_bytes=raw[195:].hex(' '),monotonic_129=all(a<=b for a,b in zip(samples[:128],samples[1:129])))
  other=target if name=='MO27Q2A' else donor
  match=other.find(raw); row['other_image_exact_match']=hex(match) if match>=0 else None
  out.append(row)
report={'warning':'No measured nits. 129 packed 12-bit samples inferred from shape; metadata bytes and interpolation not yet verified.', 'slots':out}
for ti in [8,9]:
 t=next(r for r in out if r['image']=='FO27Q3' and r['index']==ti)
 t['donor_differences']=[dict(index=r['index'],changed_bytes=sum(a!=b for a,b in zip(bytes.fromhex(t['raw']),bytes.fromhex(r['raw'])))) for r in out if r['image']=='MO27Q2A']
(ROOT/'research/hdr_tables.json').write_text(json.dumps(report,indent=2))
for r in out:
 print(r['image'],r['index'],r['offset'],'match',r['other_image_exact_match'],'monotonic',r['monotonic_129'],'metadata',r['trailing_bytes'])
print('FO27Q3 custom-table differences:',[(r['index'],r['donor_differences']) for r in out if 'donor_differences' in r])
