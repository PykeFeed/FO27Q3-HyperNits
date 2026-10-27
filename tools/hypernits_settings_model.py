"""Candidate settings/migration specification, NOT executable monitor firmware.

Reserving bits5..7 of HDR byte1 is NOT yet approved by a complete alias audit.
Tag 10 in bits7..6 distinguishes proposed records from stock defaults. It cannot
identify arbitrary historical/corrupt data that already happens to carry tag10.
"""
import json
from trace_mips import ROOT

TAG_MASK=0xc0; TAG=0x80; ENABLE=0x20; STOCK_FIELDS=0x1f; PEAK=4

def migrate(record,mode,read_ok=True):
    """Return working bytes and whether immediate save of SAME mode is needed.

    Failed reads must not trigger a write. Clear a mode4 working tag to prevent
    stale On state; preserve all existing lower fields and other-mode records.
    """
    if len(record)!=5:raise ValueError('Expected five-byte HDR record')
    out=bytearray(record)
    if mode!=PEAK:return bytes(out),False
    if not read_ok:
        out[1]&=STOCK_FIELDS
        return bytes(out),False
    if out[1]&TAG_MASK==TAG:return bytes(out),False
    out[1]=(out[1]&STOCK_FIELDS)|TAG
    return bytes(out),True

def enabled(record,mode,hdr_active=True,read_ok=True):
    return bool(read_ok and hdr_active and mode==PEAK and
                record[1]&TAG_MASK==TAG and record[1]&ENABLE)

def set_pending(record,mode,pending):
    """Stock dynamic value string448 encodes 0=On, 1=Off."""
    if mode!=PEAK:raise ValueError('Control applies only to Peak1000')
    if pending not in (0,1):raise ValueError('On/Off pending value must be 0 or 1')
    out=bytearray(record)
    out[1]=(out[1]&STOCK_FIELDS)|TAG|(ENABLE if pending==0 else 0)
    return bytes(out)

def table_slot(record,mode,variant,hdr_active=True,read_ok=True):
    """Donor slot numbering for the existing type5 path, not target array indices.

    Target F05 has no slots12/13 yet; injected pointers still need allocation.
    Callers must keep other builder paths stock.
    """
    if variant not in (0,1):raise ValueError('Variant must be zero or one')
    active=enabled(record,mode,hdr_active,read_ok) and ((record[1]>>3)&3)==2
    return (12 if active else 8)+variant

def verify():
    cases=0
    for raw in range(256):
        original=bytes([0x41,raw,0x64,0x32,0x5a])
        for mode in range(6):
            updated,dirty=migrate(original,mode)
            assert updated[0:1]+updated[2:]==original[0:1]+original[2:]
            assert updated[1]&STOCK_FIELDS==raw&STOCK_FIELDS
            assert migrate(updated,mode)==(updated,False)
            failed=bytearray(original)
            if mode==PEAK:failed[1]&=STOCK_FIELDS
            assert migrate(original,mode,False)==(bytes(failed),False)
            if mode!=PEAK:assert updated==original and not dirty
            elif raw&TAG_MASK!=TAG:assert dirty and not enabled(updated,mode)
            cases+=1
        for pending in (0,1):
            changed=set_pending(original,PEAK,pending)
            assert changed[1]&STOCK_FIELDS==raw&STOCK_FIELDS
            assert enabled(changed,PEAK)==(pending==0)
            assert not enabled(changed,PEAK,hdr_active=False)
            for variant in (0,1):
                expected=(12 if pending==0 and (raw>>3)&3==2 else 8)+variant
                assert table_slot(changed,PEAK,variant)==expected
                assert table_slot(changed,PEAK,variant,read_ok=False)==8+variant
                cases+=1
    # Every stock default is untagged; reset must leave Boost Off.
    for raw in (0x08,0x10,0x08,0x11,0x10,0x10):
        reset=bytes([0,raw,100,50,0])
        assert not enabled(reset,PEAK)
        migrated,_=migrate(reset,PEAK)
        assert not enabled(migrated,PEAK)
    report={'status':'PASS: reference model only; no firmware patch',
            'enumerated_cases':cases,'candidate_storage_mask':'0xe0',
            'unresolved':['Full ownership of bits5..7','Historical records coinciding with marker',
                          'Hardware execution/persistence and image integrity']}
    (ROOT/'research/hypernits_settings_model_checks.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':verify()
