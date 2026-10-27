#!/usr/bin/env python3
"""Interactive helper: official F05 firmware .exe  ->  ready-to-run FO27Q3_HyperNits_AllInOne.exe

Asks where the official F05 firmware .exe is, extracts them, checks the hashes, and compiles the
all-in-one flasher (flasher/aio/flasher_aio.c + flasher/patch_data.h) with the vendor files embedded.
It never flashes anything. The resulting exe starts with a menu: 1 = dry run, 2 = full flash.
PERSONAL USE ONLY: the exe contains vendor files, never publish it.
Needs: Python 3.8+, internet for 'pip install py7zr ziglang' (done automatically if missing).
"""
import argparse,hashlib,io,os,re,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
F05_SHA='abe67e9130746a19762c3395538d05c758a9bbf228f3219f6060c78416bf62b6'
F03_SHA='219d048d93d013640e6a18166da6e4471c1563f8f771cebda30ce04d9636498c'
NEED=['F05.bin','RFlash.dll','RTKCmd_x64.dll','RtHIDlib.dll','UpdFW_RTK.exe','upd.xml']
sha=lambda b:hashlib.sha256(b).hexdigest()
def die(m):print('\nERROR:',m);input('Press Enter to close...') if sys.stdin.isatty() else None;sys.exit(1)
def pip_import(mod,pkg):
 try:return __import__(mod)
 except ImportError:
  print(f'Installing {pkg} (pip)...')
  cmd=[sys.executable,'-m','pip','install','--quiet',pkg]
  if subprocess.call(cmd)!=0:subprocess.call(cmd+['--break-system-packages'])
  try:return __import__(mod)
  except ImportError:die(f'Could not install {pkg}. Run: {sys.executable} -m pip install {pkg}')
def ask_path(prompt,default_name,required=True):
 while True:
  s=input(prompt).strip().strip('"').strip("'")
  if not s:
   if not required:return None
   print('A path is required.');continue
  p=Path(s).expanduser()
  if p.is_dir():
   hits=sorted(p.glob(default_name+'*.exe'))
   if hits:p=hits[0];print('  using',p)
  if p.is_file():return p
  print('  File not found, try again.')
def extract(exe,dest):
 """Official packages are 7-Zip self-extractors: the 7z archive follows the SFX stub."""
 py7zr=pip_import('py7zr','py7zr');d=exe.read_bytes();sig=b"7z\xbc\xaf'\x1c";i=-1
 while True:
  i=d.find(sig,i+1)
  if i<0:die(f'No extractable archive found in {exe.name}. Open it with 7-Zip instead and point this script to the extracted FWUPD folder.')
  try:
   z=py7zr.SevenZipFile(io.BytesIO(d[i:]));names=z.getnames()
   if any(n.endswith('.bin') for n in names):
    dest.mkdir(parents=True,exist_ok=True);z.extractall(dest);return dest/'FWUPD'
  except Exception:pass
def main():
 ap=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
 ap.add_argument('--f05');ap.add_argument('--f03');ap.add_argument('--out',default=str(ROOT))
 a=ap.parse_args()
 print('FO27Q3 HyperNits - flasher builder (EXPERIMENTAL, use at your own risk; modified firmware voids the warranty)\n')
 f05=Path(a.f05) if a.f05 else ask_path('Path to the official FO27Q3 F05 firmware .exe (AORUS_FO27Q3_F05.exe): ','AORUS_FO27Q3_F05')
 f03=Path(a.f03) if a.f03 else None # optional advanced cross-check, only via --f03
 work=ROOT/'build_work';shutil.rmtree(work,ignore_errors=True);work.mkdir()
 print('\n[1/4] Extracting',f05.name);fw=extract(f05,work/'f05')
 for n in NEED:
  if not (fw/n).is_file():die(f'{n} missing from {f05.name}')
 if sha((fw/'F05.bin').read_bytes())!=F05_SHA:die('F05.bin does not match the expected official F05 hash. This project only supports the official F05 package.')
 print('      F05.bin hash OK')
 hdr=(ROOT/'flasher/patch_data.h').read_text()
 if F05_SHA not in hdr:die('flasher/patch_data.h was generated for a different stock image.')
 if f03:
  print('[2/4] Cross-checking against',f03.name);fw3=extract(f03,work/'f03');b=(fw3/'F03.bin').read_bytes() if (fw3/'F03.bin').is_file() else b''
  if sha(b)!=F03_SHA:print('      WARNING: F03.bin hash differs from the expected one; skipping cross-check.')
  else:
   import struct
   data=bytearray()
   for m in re.finditer(r'run\d+\[\]=\{([\d,]+)\}',hdr):data+=bytes(int(x) for x in m.group(1).split(','))
   ok=True
   for idx in (10,11,12,13):
    o=struct.unpack_from('<I',b,0x1333a4+4*idx)[0]-0x86000000
    ok&=bytes(b[o:o+197]) in bytes(data)
   print('      donor Medium/High tables found in the patch data:',ok)
   if not ok:die('Patch data does not contain the expected F03 tables.')
 else:print('[2/4] Patch data check skipped (no F03 given)')
 print('[3/4] Compiling the all-in-one flasher (zig)');pip_import('ziglang','ziglang')
 bd=work/'aio';(bd/'emb').mkdir(parents=True)
 for n in NEED:shutil.copy(fw/n,bd/'emb'/n)
 shutil.copy(ROOT/'flasher/aio/flasher_aio.c',bd);shutil.copy(ROOT/'flasher/patch_data.h',bd)
 exe=Path(a.out)/'FO27Q3_HyperNits_AllInOne.exe'
 r=subprocess.run([sys.executable,'-m','ziglang','cc','-target','x86_64-windows-gnu','-O2','-o',str(exe),'flasher_aio.c'],cwd=bd)
 if r.returncode:die('Compilation failed.')
 shutil.rmtree(work,ignore_errors=True)
 print(f'[4/4] Done: {exe}\n\nNext: run it. Choose 1 (dry run) first - it flashes nothing. Only choose the full flash after you have a verified SPI backup\nand accept that a failed flash can brick the monitor. Do not share this exe (it contains vendor files).')
 if sys.stdin.isatty():input('\nPress Enter to close...')
main()
