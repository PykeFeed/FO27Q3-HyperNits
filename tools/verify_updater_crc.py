"""Offline emulation of ONLY RFlash.dll's pure buffer-check function.

No DLL is loaded into Windows, no updater entry point runs, and no imports or
device I/O are permitted. Unicorn executes the isolated x86-64 checksum routine;
its compiler stack-cookie check is the only external call, stubbed to return.
"""
from pathlib import Path
import sys,json,hashlib
sys.path.insert(0,str(Path(__file__).resolve().parent/'re_deps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_RAX
ROOT=Path(__file__).resolve().parents[1]
path=ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/RFlash.dll';pe=pefile.PE(str(path));BASE=pe.OPTIONAL_HEADER.ImageBase
uc=Uc(UC_ARCH_X86,UC_MODE_64);uc.mem_map(BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);uc.mem_write(BASE,pe.get_memory_mapped_image())
STACK=0x10000000;DATA=0x20000000;STOP=0x30000000
uc.mem_map(STACK,0x20000);uc.mem_map(DATA,0x20000);uc.mem_map(STOP,0x1000)
def guard(machine,address,size,user):
 if address==BASE+0x20960:
  sp=machine.reg_read(UC_X86_REG_RSP);ret=int.from_bytes(machine.mem_read(sp,8),'little')
  machine.reg_write(UC_X86_REG_RSP,sp+8);machine.reg_write(UC_X86_REG_RIP,ret)
 elif not BASE+0x13c0<=address<BASE+0x19e9:raise AssertionError(f'Unexpected execution {address:#x}')
uc.hook_add(UC_HOOK_CODE,guard)
def emulate(data):
 sp=STACK+0x10000-8;uc.mem_write(sp,STOP.to_bytes(8,'little'))
 if data:uc.mem_write(DATA,data)
 uc.reg_write(UC_X86_REG_RSP,sp);uc.reg_write(UC_X86_REG_RCX,DATA);uc.reg_write(UC_X86_REG_RDX,len(data))
 uc.emu_start(BASE+0x13c0,STOP,count=max(10000,1000*len(data)))
 assert uc.reg_read(UC_X86_REG_RIP)==STOP
 return uc.reg_read(UC_X86_REG_RAX)&255
def crc8(data):
 c=0
 for b in data:
  c^=b
  for _ in range(8):c=((c<<1)^0x07)&255 if c&128 else(c<<1)&255
 return c
vectors=[b'',b'123456789',bytes(range(256)),b'\xff'*257,b'\x00'*257]
vectors.extend(bytes([b])for b in range(256))
vectors.extend(bytes(((i*73+j*19)&255)for j in range(i))for i in range(1,65))
for v in vectors:assert emulate(v)==crc8(v),(v[:10],emulate(v),crc8(v))
table=[crc8(bytes([i]))for i in range(256)]
def fast(data):
 c=0
 for b in data:c=table[c^b]
 return c
stock=(ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/F05.bin').read_bytes()
candidate=(ROOT/'experimental/FO27Q3_F05_HyperNits/F05_HyperNits_EXPERIMENTAL_NOT_FLASH_VALIDATED.bin').read_bytes()
assert len(stock)==len(candidate)and len(stock)%65536==0
banks=[]
for i in range(len(stock)//65536):
 a=stock[i*65536:(i+1)*65536];b=candidate[i*65536:(i+1)*65536]
 banks.append({'bank':i,'offset':hex(i*65536),'stock_crc8':hex(fast(a)),
  'candidate_crc8':hex(fast(b)),'changed_bytes':sum(x!=y for x,y in zip(a,b))})
report={'status':'PASS: isolated checksum function matches CRC-8 poly07/init00/nonreflected/xorout00',
 'RFlash_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'RFlash_function_rva':'0x13c0',
 'emulated_vectors':len(vectors),'check_123456789':hex(crc8(b'123456789')),
 'candidate_sha256':hashlib.sha256(candidate).hexdigest(),'bank_size':65536,'banks':banks,
 'changed_banks':[b['bank']for b in banks if b['changed_bytes']],
 'limitations':['No updater/device communication executed','No embedded/boot integrity conclusion',
 'Computed transfer CRC is not an image signature or proof of updater acceptance']}
(ROOT/'research/updater_crc_verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k]for k in ['status','emulated_vectors','check_123456789','changed_banks']},indent=2))
