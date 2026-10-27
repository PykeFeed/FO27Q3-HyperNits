"""READ-ONLY DDC/CI probe for Windows (ctypes + dxva2).

v1 was run by the user on 2026-10-26 (results in track_progress.md). v2 additionally:
prints the Windows monitor device name, parses the capability string, and reads every
declared VCP code (plus a few undeclared ones, flagged) so replies can be compared.
It only calls CapabilitiesRequestAndCapabilitiesReply and GetVCPFeatureAndVCPFeatureReply
(reads). It never calls SetVCPFeature or SaveCurrentSettings, never touches the ISP/flash
path (I2C 0x4A), never runs the Gigabyte updater/DLLs. Do not extend it to write without
reading track_progress.md. NOTE: reading an UNDECLARED code is still a Get VCP request.

Usage (Windows PowerShell):  python tools/ddcci_readonly_probe.py > ddcci_probe_output.txt
"""
import ctypes,ctypes.wintypes as w,re
user32=ctypes.windll.user32;dxva2=ctypes.windll.dxva2
class PHYS(ctypes.Structure):_fields_=[('h',w.HANDLE),('desc',ctypes.c_wchar*128)]
class MI(ctypes.Structure):_fields_=[('cb',w.DWORD),('rc',w.RECT),('work',w.RECT),('flags',w.DWORD),('dev',ctypes.c_wchar*32)]
mons=[]
CB=ctypes.WINFUNCTYPE(ctypes.c_int,w.HMONITOR,w.HDC,ctypes.POINTER(w.RECT),w.LPARAM)
user32.EnumDisplayMonitors(None,None,CB(lambda h,dc,r,l:(mons.append(h) or 1)),0)
NAMES={0x02:'new control value',0x04:'restore factory defaults (DO NOT SET)',0x05:'restore brightness/contrast',0x06:'restore geometry',0x08:'restore color defaults',0x0B:'color temp increment',0x0C:'color temp request',0x10:'brightness',0x12:'contrast',0x14:'select color preset',0x16:'red gain',0x18:'green gain',0x1A:'blue gain',0x52:'active control',0x60:'input source',0x87:'sharpness',0xAC:'h freq',0xAE:'v freq',0xB2:'flat panel sub-pixel layout',0xB6:'display technology type',0xC6:'app enable key',0xC8:'display controller type',0xCA:'OSD/button control',0xCC:'OSD language',0xD6:'power mode',0xDF:'VCP version',0xFD:'(reserved/mfr?)',0xFF:'(reserved/mfr?)'}
def get(h,c):
    t=w.DWORD();cur=w.DWORD();mx=w.DWORD()
    ok=dxva2.GetVCPFeatureAndVCPFeatureReply(h,w.BYTE(c),ctypes.byref(t),ctypes.byref(cur),ctypes.byref(mx))
    return (t.value,cur.value,mx.value) if ok else None
for hm in mons:
    mi=MI();mi.cb=ctypes.sizeof(MI);user32.GetMonitorInfoW(hm,ctypes.byref(mi))
    n=w.DWORD()
    if not dxva2.GetNumberOfPhysicalMonitorsFromHMONITOR(hm,ctypes.byref(n)) or not n.value:continue
    arr=(PHYS*n.value)();dxva2.GetPhysicalMonitorsFromHMONITOR(hm,n,arr)
    for p in arr:
        print(f'=== {p.desc} on {mi.dev}')
        caps=''
        L=w.DWORD()
        if dxva2.GetCapabilitiesStringLength(p.h,ctypes.byref(L)) and L.value:
            buf=ctypes.create_string_buffer(L.value)
            if dxva2.CapabilitiesRequestAndCapabilitiesReply(p.h,buf,L):caps=buf.value.decode('latin1');print('Capabilities:',caps)
        m=re.search(r'vcp\((.*)\)mswhql',caps)
        declared=sorted({int(x,16) for x in re.findall(r'\b([0-9A-F]{2})\b',re.sub(r'\([^)]*\)','',m[1]))}) if m else []
        probe=sorted(set(declared)|{0xE0,0xF0,0xDC,0xC0,0xC2})
        for c in probe:
            r=get(p.h,c);tag='declared' if c in declared else 'UNDECLARED'
            if c==0x04: print(f'VCP 0x{c:02X} skipped (factory reset code)');continue
            print(f'VCP 0x{c:02X} [{tag}] {NAMES.get(c,"")}:',f'type={r[0]} cur={r[1]} max={r[2]}' if r else 'no reply')
        dxva2.DestroyPhysicalMonitor(p.h)
