# FO27Q3 Hypernits

**Use at your own risk.** Flashing modified firmware will, of course, void your monitor's warranty. I am not responsible for any damage to a monitor, including a bricked monitor, caused by this project or anything built from it. The risk must be evaluated by the user before flashing anything.

Research project that ports the **HyperNits (Off / Medium / High)** HDR setting, found in the MO27Q2A F03
firmware, to the AORUS FO27Q3, firmware **F05**.

No firmware, updater or vendor DLL is included in this repository, and none must be added. You supply the official
F05 package (and the MO27Q2A F03 package for the donor tables) yourself; the tools only apply a small byte patch.

## Why MO27Q2A F03 is the donor
- Its HyperNits **Off** tables are **byte-identical** to the FO27Q3 F05 stock Off tables (both panel variants, 197 bytes each; verified), so the donor's Medium/High tables share the FO27Q3 baseline scale. No rescaling needed.
- The F03 feature only selects a table (setter checked: bits 5-6 of the HDR record byte, then the usual blank/reload/unblank refresh); no other register or state.
- Medium/High are ~0.99x Off up to index ~64, rising to ~1.50x / ~1.58x near index 84-88, 1.0 at the plateau; all clip at 4092.
- Caveat: identical Off tables support compatibility but do not prove identical panel behaviour (the MO27Q2A panel string differs).

## What the patch does
- Adds menu item ID 198 **HyperNits: Off / Medium / High** to the HDR settings, shown only for HDR mode **Peak1000**.
- Stored as in the donor firmware: bits 5-6 of the HDR settings record byte+1 (0 Off, 1 Medium, 2 High).
- The table selector (stock `0xd6238`) returns the F03 Medium/High table (per panel variant) when active, else the stock Off table.
- `apl_override` (call at `0xe3ea4`) makes the stock custom-table builder reach the selector without requiring APL = High.
- A hook at the string lookup (`0x86020de8`) provides the Off/Medium/High value labels (string group 399).
- Hooks live in unused flash at file offset `0x131000` and use absolute jumps with explicit nops, so they behave the same with or without MIPS delay slots.

## Status / known gaps
- Hardware testing so far: **one single unit** (my own FO27Q3). The current Off / Medium / High build is running on that unit with no issues observed so far; it has also passed the simulator (28,651 cases in each of 3 delay models).
- Not independently verified: the value-string group, use of bit 6, execution from the extra flash area, boot-time integrity checks, whether the vendor updater accepts a modified same-version image on every unit.
- No verified recovery route; dump and test-restore the SPI flash first.

## How to use this repo

### Quick path (builds a ready-to-flash exe)
1. Download the official FO27Q3 **F05** package (`AORUS_FO27Q3_F05.exe`) yourself (nothing vendor-owned is in this repo).
2. Install [Python 3](https://www.python.org/downloads/) and run **`make_flasher.bat`** (or `python tools/make_flasher.py`). It asks where the F05 firmware `.exe` is, extracts it, checks the F05 hash, and builds `FO27Q3_HyperNits_AllInOne.exe` next to it. It needs internet once to `pip install py7zr ziglang`. Nothing is flashed by this step.
3. Run `FO27Q3_HyperNits_AllInOne.exe`. Choose **1 (dry run)** first. Only choose the full flash after you have a verified SPI backup and accept the risks above. The built exe contains vendor files: personal use only, never share it.

### Extracting the firmware `.exe` manually
The official packages are 7-Zip self-extracting archives, so they are not installers you have to run:
1. Install [7-Zip](https://www.7-zip.org/).
2. Right-click `AORUS_FO27Q3_F05.exe` -> **7-Zip -> Extract to "AORUS_FO27Q3_F05\"** (or run `7z x AORUS_FO27Q3_F05.exe -oextracted/AORUS_FO27Q3_F05`). Do **not** double-click the `.exe`: that launches Gigabyte's updater.
3. You get a `FWUPD` folder with `F05.bin`, `UpdFW_RTK.exe`, `RFlash.dll`, `RtHIDlib.dll`, `RTKCmd_x64.dll`, `upd.xml`. That is all you need to flash with the launcher (`flasher/FO27Q3_HyperNits_Flasher.exe`). Only if you rebuild the patch from source (see below), extract `MO27Q2A_F03.exe` the same way (it contains `F03.bin`).
4. For the build tools, keep them at `extracted/AORUS_FO27Q3_F05/FWUPD/` (and `extracted/MO27Q2A_F03/FWUPD/` if you rebuild from source).

### Rebuilding the patch from source (advanced)
1. Extract both packages as above and check the hashes listed below.
2. Build the patched image with a mipsel binutils that supports MIPS16 (see Build and verify): `python tools/build_hypernits.py`.
3. Verify it: run `tools/verify_hypernits.py` with `HOOK_DELAY=none`, `jump` and `jump+branch`; all three must pass.
4. Regenerate the flasher data with `python tools/make_flasher_patch_header.py`, then run `make_flasher.bat` again.

Folders: `patch/` hook source (`hypernits.S`), `tools/` build/verify/analysis scripts, `flasher/` launcher sources and patch data, `experimental/` build reports (images are not stored), `research/` small evidence files.

## Build and verify (needs the official files)
Local inputs, not in this repo: official FO27Q3 `F05.bin`, MO27Q2A `F03.bin`, and a mipsel binutils with MIPS16 support.
```
python tools/build_hypernits.py
HOOK_DELAY=none python tools/verify_hypernits.py      # also: jump, jump+branch
python tools/make_flasher_patch_header.py
```
Hashes (SHA-256):
- Official F05.bin: `abe67e9130746a19762c3395538d05c758a9bbf228f3219f6060c78416bf62b6`
- MO27Q2A F03.bin (donor): `219d048d93d013640e6a18166da6e4471c1563f8f771cebda30ce04d9636498c`
- Patched candidate: `e305e1401c0b462000050b36a73c248b8e31287da5d7790f5e073ed49e167e4c`

## Using the launcher
Put the exe next to the official `FWUPD` folder (or pass `--fwupd <dir>`). With no options it only verifies the vendor files,
applies the patch in memory, checks the result against the expected hash and writes a flash package: a **dry run**.
`--flash` additionally requires typing YES (verified SPI backup) and `FLASH MY FO27Q3`, then starts the official vendor updater.

## License
The original code in this repository (hook source, build/verify/flasher tools and scripts) is licensed under the **GNU General Public License v3.0**; see [LICENSE](LICENSE). It comes with no warranty, as stated in the license and in the risk notice at the top.

The license does not cover third-party material: Gigabyte's firmware, updater and DLLs are not included and remain their owner's property, and the patch data contains small table excerpts derived from the MO27Q2A F03 firmware, which stay under their original rights.

## Legal
Unofficial and unaffiliated with Gigabyte or Realtek. Patch bytes include small table excerpts derived from the MO27Q2A F03 firmware.
Do not redistribute vendor firmware, updaters, DLLs or built all-in-one executables.
