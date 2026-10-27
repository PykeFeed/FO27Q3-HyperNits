"""Record verified edit sites and unresolved integration requirements. No patch."""
import hashlib,json
from trace_mips import ROOT
d=(ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/F05.bin').read_bytes()
assert hashlib.sha256(d).hexdigest()=='abe67e9130746a19762c3395538d05c758a9bbf228f3219f6060c78416bf62b6'
sites=[]
for offset,before,after,reason in [
 (0xfac0,'06 6b','07 6b','HDR adjustment descriptor item33..39: row count6 ->7'),
 (0x15d10,'06 6d','07 6d','Category24 joystick navigation: row count6 ->7'),
 (0x16750,'05 5a','06 5a','Entry skip-disabled loop: keep Reset Picture as fallback at new row6')]:
 assert d[offset:offset+2]==bytes.fromhex(before)
 sites.append(dict(offset=hex(offset),expected_original=before,proposed=after,reason=reason))
assert d[0xe9548:0xe9550]==bytes.fromhex('3a 39 37 36 35 38 ff ff')
report={'status':'INCOMPLETE INTEGRATION REQUIREMENTS; NOT A PATCH MANIFEST TO APPLY',
 'simple_edit_sites_after_full_hooks_exist':sites,
 'row_list':{'offset':'0xe9548','expected_original':'3a 39 37 36 35 38 ff ff',
  'proposed_symbolic':'3a 39 37 36 35 NEW_ID 38 ff'},
 'do_not_change':['0x14d60/0x14d6e: picture-mode count, not adjustment rows',
  '0x17714: range of HDR descriptor IDs33..39, not adjustment row count',
  '0x16290/0x162f0: generic seven-row pagination boundaries'],
 'hooks_required':{'descriptor':'0xf900','availability':'0x15268','row_label429':'0x21514',
  'live_commit':'0x11324','confirm_handler_review':'0x11ac0',
  'selector':'0xd6238','load_migration':'0x7694','persistent_write':'0x7b24'},
 'experimental_implementation':'experimental/FO27Q3_F05_HyperNits/build_report.json',
 'experimental_menu_id':198,
 'unresolved':['Complete ID/storage alias and historical audit','Executable mapping/processor semantics',
  'Native refresh timing','Firmware integrity and hardware checks'],
 'shared_menu_scope':'Counts/list shared across HDR modes. Global 7-row edit needs new row disabled outside Peak1000; strict hiding requires conditional lists/counts.',
 'on_off_pending':{'0':'On','1':'Off','dynamic_string':448}}
(ROOT/'research/hypernits_integration_requirements.json').write_text(json.dumps(report,indent=2)+'\n')
print('Verified three original instruction sites; wrote incomplete integration requirements. No firmware modified.')
