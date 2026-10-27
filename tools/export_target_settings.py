"""Export hash-guarded FO27Q3 menu/settings evidence. Reads firmware only."""
import hashlib,json
from trace_mips import ROOT,load

data=(ROOT/'extracted/AORUS_FO27Q3_F05/FWUPD/F05.bin').read_bytes()
digest=hashlib.sha256(data).hexdigest()
assert digest=='abe67e9130746a19762c3395538d05c758a9bbf228f3219f6060c78416bf62b6'
def pointer(offset):return int.from_bytes(data[offset:offset+4],'little')
assert data[0xe9548:0xe9550]==bytes.fromhex('3a 39 37 36 35 38 ff ff')
assert pointer(0xe99fc+4*(452-389))==0x86021829
report={
 'image_sha256':digest,'address_convention':'File offsets unless explicitly RAM/runtime.',
 'hdr_record':{'ram':'0xa0101a74','length':5,'nvram_offset_formula':'148 + 5*hdr_mode',
  'peak1000_mode':4,'peak1000_nvram_offsets':[168,172],
  'load':'0x7694','save':'0x7b24','reset':'0x7940','default_table':'0x10e9ec',
  'default_records':[data[0x10e9ec+5*i:0x10e9f1+5*i].hex(' ')for i in range(6)],
  'default_on_reset_boost_bit5':False,
  'proposed_boost_bit':{'ram':'0xa0101a75','mask':'0x20','experimental_schema_mask':'0xe0',
      'status':'Used by isolated experimental candidate; global alias/ownership audit and historical marker collisions unresolved.'}},
 'save_event':{'schedule_wrapper':'0xdfdb4','scheduler':'0xb307c','delay_argument':1000,
  'event':23,'dispatcher':'0xf19c','case':'0xf38e','writer':'0x7b24'},
 'menu':{'category':24,'row_table':'0xe9548','items':list(data[0xe9548:0xe954e]),
  'row_names':['Brightness','Contrast','Light Enhance','Color Enhance','Dark Enhance','Reset Picture'],
  'row_label_string_id':429,'row_label_case':'0x21514',
  'picture_mode_count_getter_do_not_patch':'0x14d60',
  'hdr_row_navigation_count_instruction':'0x15d10',
  'hdr_descriptor_count_instruction':'0xfac0',
  'entry_disabled_skip_bound_instruction':'0x16750',
  'on_off_value_string':{'id':448,'pending0':'On','pending1':'Off'},
  'experimental_row_insertion':'Original 8 bytes become 7 IDs plus FF terminator; item198 before Reset Picture.',
  'experimental_menu_id':198,
  'row_mapper':'0x14c78','descriptor_builder':'0xf900','commit_dispatcher':'0x11324',
  'pending_ram':'0xa0101892','availability':'0x15268',
  'item60_collision':True,'item60_existing_commit_case':'0x11a6a',
  'table_reference_sites':['0x14ccc','0x16734','0x17718','0x1791c']},
 'existing_apl_setting':{'item':79,'descriptor':'0x110d4','value_string_id':452,
  'getter':'0xdf08','setter':'0xe550','apply_and_save':'0x9204',
  'commit_dispatcher':'0x18a7c','commit_case':'0x18ada','mask':'0x18','ram':'0xa0101a75',
  'values':{'0':'Low','1':'Middle','2':'High'},
  'peak1000_type5_requires_value':2},
 'limitations':['Experimental candidate exists; no hardware or flashing validation','No exhaustive alias analysis',
  'No hardware save/power-cycle validation','No firmware integrity scheme established']}
rows=load('FO27Q3')
ranges=[(0x7694,0x76b4),(0x7940,0x7974),(0x7b24,0x7b44),(0x89ac,0x8a9c),
 (0x9204,0x9284),(0xdf08,0xdf34),(0xe550,0xe598),(0xf19c,0xf212),(0xf38e,0xf39a),
 (0xf900,0xf96e),(0xfeb0,0xff46),(0x110d4,0x110f6),(0x11324,0x1140e),
 (0xfa92,0xfad8),(0xfccc,0xfd1e),(0x1156a,0x115ae),(0x119b0,0x11b90),(0x14c78,0x14ce4),(0x14d60,0x14d78),(0x1559e,0x155b0),
 (0x150e4,0x15268),(0x15c80,0x15d3a),(0x16024,0x160b8),(0x1623c,0x162fc),
 (0x26138,0x261da),(0x26256,0x2632a),
 (0x16720,0x16780),(0x1770e,0x17728),(0x178ec,0x17928),(0x18a7c,0x18aea),
 (0x20de8,0x20e30),(0x21514,0x21592),(0x21828,0x21844),(0x218d2,0x218e6),(0x21cdc,0x21d24),(0x22018,0x22030),
 (0x25e9c,0x25eb4),(0x26af8,0x26b24),(0x26e48,0x26e94),
 (0xb307c,0xb30e0),(0xde5cc,0xde5f8),(0xde644,0xde674)]
text=[]
for start,end in ranges:
 text.append(f'\n; FILE 0x{start:x}..0x{end:x}, end exclusive')
 text.extend(r['line']for r in rows if 0x86000000+start<=r['address']<0x86000000+end)
(ROOT/'research/FO27Q3.settings_evidence.asm').write_text('\n'.join(text)+'\n')
(ROOT/'research/FO27Q3.settings_map.json').write_text(json.dumps(report,indent=2)+'\n')
print('Exported target settings map and bounded disassembly evidence; original hash verified.')
