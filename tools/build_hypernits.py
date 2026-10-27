"""Build isolated, hash-guarded experimental firmware. Does not run any updater.

The candidate has no verified image integrity fix or hardware execution test.
Do not treat successful assembly/static tests as authorization to flash it.
"""
from pathlib import Path
import hashlib,json,subprocess,os
from trace_mips import ROOT

OUT=ROOT/os.environ.get('HOOK_OUT','experimental/FO27Q3_F05_HyperNits');OUT.mkdir(parents=True,exist_ok=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
stock=(ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/F05.bin').read_bytes()
donor=(ROOT/'extracted/MO27Q2A_F03/FWUPD/F03.bin').read_bytes()
DONOR_SHA='219d048d93d013640e6a18166da6e4471c1563f8f771cebda30ce04d9636498c'
assert sha(stock)=='abe67e9130746a19762c3395538d05c758a9bbf228f3219f6060c78416bf62b6'
assert sha(donor)==DONOR_SHA
for level,base in (('medium',10),('high',12)): # F03 pointer table 0x1333a4: idx10/11 Medium, idx12/13 High
 for variant in (0,1):
  q=0x1333a4+4*(base+variant);o=int.from_bytes(donor[q:q+4],'little')-0x86000000
  lut=donor[o:o+197];assert len(lut)==197 and lut[195]==0x3b and lut[196] in (0x4a,0x4b)
  (OUT/f'{level}_variant{variant}.lut').write_bytes(lut)

sites=[('descriptor',0xf904,8,'descriptor_hook'),('availability',0x1526c,6,'availability_hook'),
       ('commit',0x11328,6,'commit_hook'),('label',0x21514,6,'label_hook'),
       ('load',0x7698,8,'load_hook'),('apl',0xe3ea4,4,'apl_override')]
special=[('selector',0xd6238,'selector_hook','a3'),('valuetext',0x20de8,'value_text_hook','v1')]
source=['.set mips16','.set noreorder']
for name,off,size,target in sites:
 source.extend([f'.section .patch_{name},"ax",@progbits',f'jal {target}'])
 source.extend(['nop']*((size-4)//2))
for name,off,target,reg in special:
 source.extend([f'.section .patch_{name},"ax",@progbits',f'lui ${reg},%hi({target})',f'addiu ${reg},%lo({target})',f'jr ${reg}','nop'])
(OUT/'sites.S').write_text('\n'.join(source)+'\n')
link=['OUTPUT_ARCH(mips)','SECTIONS {','.text 0x86131000 : { *(.text) }']
for name,off,size,target in sites:link.append(f'.patch_{name} {0x86000000+off:#x} : {{ *(.patch_{name}) }}')
link.extend(['.patch_selector 0x860d6238 : { *(.patch_selector) }','.patch_valuetext 0x86020de8 : { *(.patch_valuetext) }',
 '/DISCARD/ : { *(.reginfo) *(.MIPS.abiflags) *(.pdr) *(.gnu.attributes) *(.data) *(.bss) }','}'])
(OUT/'link.ld').write_text('\n'.join(link)+'\n')

rel=OUT.relative_to(ROOT).as_posix()
(OUT/'hooks_src.S').write_text((ROOT/'patch/hypernits.S').read_text().replace('@DIR@',rel))
prefix='tools/linux_binutils/extracted/usr/bin/mipsel-linux-gnu-'
script=f'''set -e
export LD_LIBRARY_PATH=tools/linux_binutils/extracted/usr/lib/x86_64-linux-gnu
{prefix}as -EL -mips32r5 -mips16 -mmips16e2 -o {rel}/hooks.o {rel}/hooks_src.S
{prefix}as -EL -mips32r5 -mips16 -mmips16e2 -o {rel}/sites.o {rel}/sites.S
{prefix}ld -T {rel}/link.ld -o {rel}/hooks.elf {rel}/hooks.o {rel}/sites.o
{prefix}nm -n {rel}/hooks.elf > {rel}/symbols.txt
{prefix}objdump -d {rel}/hooks.elf > {rel}/hooks.asm
{prefix}objcopy -O binary -j .text {rel}/hooks.elf {rel}/hooks.bin
'''
for name,_,_,_ in sites+[('selector',0,12,''),('valuetext',0,12,'')]:
 script+=f'{prefix}objcopy -O binary -j .patch_{name} {rel}/hooks.elf {rel}/site_{name}.bin\n'
result=subprocess.run(['wsl','-d','Ubuntu-26.04','--','bash','-lc',script],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
(OUT/'toolchain.log').write_text(result.stdout)
if result.returncode:raise RuntimeError(result.stdout)
symbols={}
for line in (OUT/'symbols.txt').read_text().splitlines():
 parts=line.split()
 if len(parts)==3:symbols[parts[2]]=int(parts[0],16)
assert 0x86131000<=symbols['hooks_end']<0x86133000
candidate=bytearray(stock);changes=[]
def edit(off,new,reason):
 before=stock[off:off+len(new)]
 assert not any(off<e['offset']+e['length']and off+len(new)>e['offset']for e in changes)
 candidate[off:off+len(new)]=new
 changes.append(dict(offset=off,length=len(new),before=before.hex(' '),after=new.hex(' '),reason=reason))
payload=(OUT/'hooks.bin').read_bytes()
assert stock[0x131000:0x131000+len(payload)]==b'\xff'*len(payload)
edit(0x131000,payload,'Assembled hooks, target glyphs and donor High LUT pair; formerly FF space')
for name,off,size,target in sites:
 new=(OUT/f'site_{name}.bin').read_bytes()
 assert len(new)==size,(name,len(new),size)
 edit(off,new,f'Hook {name}: {target}')
selector=(OUT/'site_selector.bin').read_bytes();assert len(selector)==12
edit(0xd6238,selector,'Tail jump into selector hook, retaining original incoming return address')
vt=(OUT/'site_valuetext.bin').read_bytes();assert len(vt)==12
assert stock[0x20de8:0x20df4].hex()=='fd63056204d07ff66b444467',stock[0x20de8:0x20df4].hex()
edit(0x20de8,vt,'Tail jump into string-lookup hook (group 399 = Off/Medium/High); stock prologue replayed by the hook')
for off,before,new,reason in [
 (0xfac0,b'\x06\x6b',b'\x07\x6b','HDR adjustment descriptor row count7'),
 (0x15d10,b'\x06\x6d',b'\x07\x6d','HDR adjustment navigation row count7'),
 (0x16750,b'\x05\x5a',b'\x06\x5a','Reset Picture remains entry fallback row6'),
 (0xe9548,bytes.fromhex('3a 39 37 36 35 38 ff ff'),bytes.fromhex('3a 39 37 36 35 c6 38 ff'),'Insert new item198 before Reset Picture')]:
 assert stock[off:off+len(before)]==before
 edit(off,new,reason)
assert len(candidate)==len(stock)
assert candidate[0x380000:]==stock[0x380000:] # Supplemental image regions untouched.
assert bytes.fromhex('21 43 4d 4a 46 3b 54 ff')in stock # Display: y glyph corroboration.
report={'status':'EXPERIMENTAL; NOT HARDWARE TESTED','input_sha256':sha(stock),
 'donor_sha256':sha(donor),'donor':'MO27Q2A F03 HyperNits tables (pointer idx10/11 Medium, idx12/13 High)','output_sha256':sha(candidate),'image_bytes':len(candidate),
 'cave_offset':'0x131000','payload_bytes':len(payload),'symbols':{k:hex(v)for k,v in symbols.items()},
 'changes':changes,'new_menu_id':198,'value_string_group':399,'storage':'HDR record byte+1 bits 5-6 (0 Off,1 Medium,2 High)'}
(OUT/'build_report.json').write_text(json.dumps(report,indent=2)+'\n')
(OUT/'F05_HyperNits.bin').write_bytes(candidate)
disassemble=f'''set -e
export LD_LIBRARY_PATH=tools/linux_binutils/extracted/usr/lib/x86_64-linux-gnu
{prefix}objdump -D -b binary -m mips:16 -EL --adjust-vma=0x86000000 --stop-address={symbols['hn_tables']:#x} {rel}/F05_HyperNits.bin > {rel}/candidate_code.asm
'''
subprocess.run(['wsl','-d','Ubuntu-26.04','--','bash','-lc',disassemble],cwd=ROOT,check=True)
(OUT/'README.md').write_text('''# FO27Q3 F05 HyperNits (Off / Medium / High) - EXPERIMENTAL

Port of the MO27Q2A F03 HyperNits feature. New HDR-menu item (ID198) with values Off / Medium / High,
stored in bits 5-6 of the HDR record byte+1 like the donor. Medium/High load the F03 Medium/High transfer tables
(both panel variants) through the stock table loader; Off keeps the stock FO27Q3 Off table. Available only in
HDR Peak 1000 mode. Not hardware tested; see build_report.json.

Why the MO27Q2A F03 donor: its HyperNits Off tables are byte-identical to the FO27Q3 F05 Off tables, so the
Medium/High tables share the FO27Q3 baseline scale; no rescaling is needed.
''')
print(json.dumps({k:report[k]for k in ['status','output_sha256','payload_bytes']},indent=2))
