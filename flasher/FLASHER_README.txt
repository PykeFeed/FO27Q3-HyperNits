FO27Q3_HyperNits_Flasher.exe  (EXPERIMENTAL - tested on one single unit only; modified firmware voids the warranty, use at your own risk, the author is not responsible for a bricked monitor)

Put the exe in the project folder (next to "extracted\AORUS_FO27Q3_F05\FWUPD") or pass --fwupd <folder>.

  FO27Q3_HyperNits_Flasher.exe                dry run: checks the official files, builds the patched package, flashes nothing
  FO27Q3_HyperNits_Flasher.exe --flash        asks for typed confirmations, then starts the OFFICIAL updater (UpdFW_RTK.exe)
                                              from FO27Q3_HyperNits_flash_package\ ; you press its update button
  --accept-no-recovery                        skip the "I have a verified SPI backup" question (you accept a possible permanent brick)
  --fwupd <dir>                               official FWUPD folder (default: auto-detect)

It refuses to continue unless every official file matches the known SHA-256 and the patched image matches
debf5480b5f8eabe96888cd4d844e0fcd5dbfcbc42659d4c8b4e7a788d9b020b.
Source: flasher.c + patch_data.h (regenerate with tools\make_flasher_patch_header.py).
Build (needs zig, e.g. "pip install ziglang"):  python -m ziglang cc -target x86_64-windows-gnu -O2 -o FO27Q3_HyperNits_Flasher.exe flasher.c
