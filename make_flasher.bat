@echo off
rem Builds your personal all-in-one flasher. Asks where the official F05 firmware .exe is.
rem Needs Python 3 (https://www.python.org). Nothing is flashed by this step.
where py >nul 2>nul
if %errorlevel%==0 (py -3 "%~dp0tools\make_flasher.py" %*) else (python "%~dp0tools\make_flasher.py" %*)
pause
