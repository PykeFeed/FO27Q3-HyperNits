/* FO27Q3 F05 "HyperNits" (Off / Medium / High).
 * Setting: bits 5-6 of HDR record byte+1 (RAM 0xa0101a75), 0 Off, 1 Medium, 2 High - the same field the MO27Q2A F03 donor uses.
 * Medium/High select the F03 transfer tables (pointer-table idx 10/11 and 12/13) instead of the stock Off table.
 * Every call/jump is followed by an explicit nop and hooks leave via absolute addresses, so behaviour is identical
 * with or without jump/branch delay slots. New menu item ID198, value-string group 399 (Off/Medium/High).
 */
.set mips16
.set noreorder
.text
.balign 4
.macro TAIL address
  lui $a3,%hi(\address)
  addiu $a3,%lo(\address)
  jr $a3
  nop
.endm
.macro xjal t
  jal \t
  nop
.endm
.macro xjr r
  jr \r
  nop
.endm
.macro xb l
  b \l
  nop
.endm
.macro xbeqz r,l
  beqz \r,\l
  nop
.endm
.macro xbnez r,l
  bnez \r,\l
  nop
.endm
.macro xbteqz l
  bteqz \l
  nop
.endm
.macro xbtnez l
  btnez \l
  nop
.endm


.balign 4
.globl descriptor_hook
.ent descriptor_hook
descriptor_hook:
  sw $s1,32($sp)
  sw $s0,28($sp)
  cmpi $a0,198
  xbteqz descriptor_new
  lui $v0,0xa010 /* Replay displaced stock instruction (site is 8 bytes). */
  TAIL 0x8600f90d
descriptor_new:
  lui $s0,0xa010
  addiu $s0,6288
  li $v0,1
  sb $v0,0($s0)
  sb $v0,8($s0)
  li $v0,2
  sh $v0,4($s0) /* Maximum 2. */
  li $v0,0
  sh $v0,6($s0) /* Minimum 0. */
  li $v0,198
  sh $v0,10($s0)
  li $v0,399
  sh $v0,12($s0) /* Value-string group: Off / Medium / High. */
  xjal get_level
  sh $v0,2($s0)
  TAIL 0x8600facf
.end descriptor_hook

/* v0 = HyperNits level from HDR record byte+1 bits 5-6: 0 Off, 1 Medium, 2 High (3 treated as High, as the donor does). */
.balign 4
.globl get_level
.ent get_level
get_level:
  lui $v0,0xa010
  lbu $v0,6773($v0)
  li $v1,0x60
  and $v0,$v1
  srl $v0,5
  cmpi $v0,3
  xbtnez get_level_done
  li $v0,2
get_level_done:
  xjr $ra
.end get_level

.balign 4
.globl applicable
.ent applicable
applicable:
  addiu $sp,-24
  sw $ra,20($sp)
  xjal 0x8600dc30
  xbeqz $v0,applicable_no
  xjal 0x86026d58
  cmpi $v0,4
  xbtnez applicable_no
  li $v0,1
  xb applicable_done
applicable_no:
  li $v0,0
applicable_done:
  lw $a3,20($sp)
  addiu $sp,24
  xjr $a3
.end applicable

/* v0 = level if the setting applies (HDR active and mode 4 = HDR Peak 1000), else 0. */
.balign 4
.globl effective_level
.ent effective_level
effective_level:
  addiu $sp,-24
  sw $ra,20($sp)
  xjal applicable
  xbeqz $v0,effective_done
  xjal get_level
effective_done:
  lw $a3,20($sp)
  addiu $sp,24
  xjr $a3
.end effective_level

.balign 4
.globl availability_hook
.ent availability_hook
availability_hook:
  sw $s0,48($sp)
  li $a2,30
  cmpi $a0,198
  xbteqz availability_new
  move $s0,$a0 /* Replay displaced stock instruction. */
  TAIL 0x86015273
availability_new:
  xjal applicable
  li $v1,1
  xor $v0,$v1 /* Disabled predicate: 1 when unavailable. */
  TAIL 0x86015407
.end availability_hook

.balign 4
.globl commit_hook
.ent commit_hook
commit_hook:
  cmpi $a0,198
  xbteqz commit_new
  sltiu $a0,126 /* Replay displaced stock dispatch. */
  xbtnez commit_low
  TAIL 0x860114a3
commit_low:
  TAIL 0x8601132f
commit_new:
  lui $v0,0xa010
  lhu $a0,6290($v0)
  xjal set_level
  TAIL 0x86011363
.end commit_hook

/* a0 = new level 0..2. Writes bits 5-6 (clearing bit 7), persists, then runs the blank / reload table / unblank refresh. */
.balign 4
.globl set_level
.ent set_level
set_level:
  addiu $sp,-32
  sw $ra,28($sp)
  sw $s0,24($sp)
  sw $s1,20($sp)
  move $s0,$a0
  sltiu $s0,3
  xbteqz setter_done
  xjal applicable
  xbeqz $v0,setter_done
  lui $s1,0xa010
  lbu $v1,6773($s1)
  li $v0,0x1f
  and $v0,$v1
  move $a0,$s0
  sll $a0,5
  or $v0,$a0
  cmp $v0,$v1
  xbteqz setter_done
  sw $v1,16($sp)
  sb $v0,6773($s1)
  li $a0,4
  xjal 0x86007b24 /* Persist originating mode before refresh or mode transition. */
  xbeqz $v0,setter_write_failed
  li $a0,32
  li $a1,1
  xjal 0x860dc258
  li $a0,33
  li $a1,1
  xjal 0x860dc258
  lbu $a0,6204($s1)
  xjal 0x860d5f24
  move $a0,$v0
  xjal 0x860da470
  li $a0,32
  li $a1,0
  xjal 0x860dc258
  li $a0,33
  li $a1,0
  xjal 0x860dc258
  xb setter_done
setter_write_failed:
  lw $v0,16($sp)
  sb $v0,6773($s1)
  xjal get_level
  sh $v0,6290($s1) /* Menu pending value back to the restored level. */
setter_done:
  lw $a3,28($sp)
  lw $s0,24($sp)
  lw $s1,20($sp)
  addiu $sp,32
  xjr $a3
.end set_level

.balign 4
.globl label_hook
.ent label_hook
label_hook:
  li $a0,24
  xjal 0x86014c78
  cmpi $v0,198
  xbteqz label_new
  TAIL 0x8602151b
label_new:
  lui $v0,%hi(hypernits_label)
  addiu $v0,%lo(hypernits_label)
  TAIL 0x86021399
.end label_hook

/* Entry of the string lookup 0x86020de8 (a0 = group, a1 = value). Group 399 is unused by the stock table. */
.balign 4
.globl value_text_hook
.ent value_text_hook
value_text_hook:
  addiu $sp,-24 /* Replay displaced stock prologue. */
  sw $ra,20($sp)
  sw $s0,16($sp)
  cmpi $a0,399
  xbteqz value_text_new
  addiu $v1,$a0,-389
  move $v0,$a0
  TAIL 0x86020df5
value_text_new:
  sltiu $a1,3
  xbtnez value_text_ok
  li $a1,0
value_text_ok:
  sll $a1,2
  lui $v0,%hi(hn_value_strings)
  addiu $v0,%lo(hn_value_strings)
  addu $v0,$a1
  lw $v0,0($v0)
  TAIL 0x86021399
.end value_text_hook

/* Retargeted call at 0x860e3ea4 (stock: jal 0x8600df08; cmpi v0,2; btnez ...). The stock type-5 custom table builder
 * only reaches the table selector when APL Stabilize == High (df08() == 2). With Medium/High active report 2. */
.balign 4
.globl apl_override
.ent apl_override
apl_override:
  addiu $sp,-32
  sw $ra,28($sp)
  xjal effective_level
  xbeqz $v0,apl_stock
  li $v0,2
  xb apl_done
apl_stock:
  xjal 0x8600df08
apl_done:
  lw $a3,28($sp)
  addiu $sp,32
  xjr $a3
.end apl_override

/* Table selector 0x860d6238 (a0 = mode value, a1 = panel variant 0/1). Medium/High -> F03 table pointer[2*(level-1)+variant];
 * otherwise the stock Off table (pointer-table entry 8+variant). */
.balign 4
.globl selector_hook
.ent selector_hook
selector_hook:
  addiu $sp,-32
  sw $ra,28($sp)
  sw $s0,24($sp)
  move $s0,$a1
  xjal effective_level
  xbeqz $v0,selector_stock
  addiu $v0,-1
  sll $v0,1
  addu $s0,$v0
  lui $v0,%hi(hn_tables)
  addiu $v0,%lo(hn_tables)
  xb selector_lookup
selector_stock:
  lui $v0,0x8613
  addiu $v0,-15500 /* 0x8612c354 + 8*4. */
selector_lookup:
  sll $s0,2
  addu $v0,$s0
  lw $v0,0($v0)
  lw $a3,28($sp)
  lw $s0,24($sp)
  addiu $sp,32
  xjr $a3
.end selector_hook

.balign 4
.globl load_hook
.ent load_hook
load_hook:
  sw $a0,16($sp) /* Original loader's unused local; save originating mode. */
  sll $v0,$a0,2
  addu $a0,$v0,$a0
  addiu $a0,127
  addiu $a0,21
  lui $a2,0xa010
  addiu $a2,6772
  li $a1,5
  xjal 0x860de5cc
  xbeqz $v0,load_failed
  lw $a0,16($sp)
  cmpi $a0,4
  xbtnez load_return
  lui $v1,0xa010
  lbu $a1,6773($v1)
  li $a2,0x80
  and $a2,$a1
  xbeqz $a2,load_return
  li $a2,0x1f /* Bit 7 only ever set by earlier experimental builds: reset the field to Off and persist. */
  and $a1,$a2
  sb $a1,6773($v1)
  xjal 0x86007b24
  li $v0,1 /* Preserve original successful-read return contract. */
  xb load_return
load_failed:
  lw $a0,16($sp)
  cmpi $a0,4
  xbtnez load_return
  lui $v1,0xa010
  lbu $a1,6773($v1)
  li $a2,0x1f
  and $a1,$a2
  sb $a1,6773($v1) /* Force Off in RAM; never persist a failed read. */
  li $v0,0
load_return:
  TAIL 0x860076af
.end load_hook

.balign 4
hn_tables:
  .word hn_medium0,hn_medium1,hn_high0,hn_high1
hn_value_strings:
  .word str_off,str_medium,str_high
.globl hypernits_label
hypernits_label:
  .byte 0x25,0x54,0x4a,0x3f,0x4c,0x2c,0x43,0x4e,0x4d,0xff
str_off:
  .byte 0x2d,0x40,0x40,0xff
str_medium:
  .byte 0x2a,0x2b,0x3f,0x3e,0x43,0x4f,0x47,0x00,0xff
str_high:
  .byte 0x25,0x43,0x41,0x42,0xff
.balign 4
.globl hn_medium0
hn_medium0:
  .incbin "@DIR@/medium_variant0.lut"
.balign 4
.globl hn_medium1
hn_medium1:
  .incbin "@DIR@/medium_variant1.lut"
.balign 4
.globl hn_high0
hn_high0:
  .incbin "@DIR@/high_variant0.lut"
.balign 4
.globl hn_high1
hn_high1:
  .incbin "@DIR@/high_variant1.lut"
.balign 4
.globl hooks_end
hooks_end:
