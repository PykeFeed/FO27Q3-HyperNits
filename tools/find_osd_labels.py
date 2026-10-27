"""Look for OSD strings with independent contiguous upper/lower glyph alphabets.
Hits are hypotheses, not proof of executable menu references.
"""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
results=[]
for path in sorted((ROOT/'extracted').rglob('*.bin'))+sorted(ROOT.glob('*109*.bin'))+sorted(ROOT.glob('*V111*.bin')):
 data=path.read_bytes()
 for word in ['HyperNits','Hypernits','EOTF','Peak','Brightness']:
  groups=[('U',ord(c)-65) if c.isupper() else ('L',ord(c)-97) for c in word]
  # All sequences must preserve differences within each letter case.
  anchor=next((i for i in range(len(word)-2) if groups[i][0]==groups[i+1][0]==groups[i+2][0]),None)
  if anchor is None: continue
  for base in range(256):
   seq=bytes((base+groups[i][1])%256 for i in range(anchor,anchor+3))
   off=0
   while (hit:=data.find(seq,off))>=0:
    off=hit+1; start=hit-anchor
    if start<0 or start+len(word)>len(data):continue
    mapping={};ok=True
    for i,(g,n) in enumerate(groups):
     v=(data[start+i]-n)%256
     if g in mapping and mapping[g]!=v:ok=False;break
     mapping[g]=v
    if ok:
     results.append(dict(file=str(path.relative_to(ROOT)),word=word,offset=hex(start),alphabet_bases=mapping,context=data[max(0,start-16):start+len(word)+32].hex(' ')))
(ROOT/'research/osd_label_candidates.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
for r in results:
 if r['word'] in ['HyperNits','Hypernits','Brightness']:print(r)
