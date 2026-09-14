@echo off
REM build_exe.bat
REM Builds ShieldChain.exe from this project folder.
REM Run this ON WINDOWS, with Python 3.10+ installed and added to PATH.

echo ================================================
echo   ShieldChain - building Windows .exe
echo ================================================

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller

echo.
echo Building executable with PyInstaller...
pyinstaller shieldchain.spec --noconfirm

echo.
if exist dist\ShieldChain.exe (
    echo SUCCESS: dist\ShieldChain.exe has been created.
    echo Double-click it to launch the dashboard in your browser.
) else (
    echo Build finished, but ShieldChain.exe was not found in dist\.
    echo Check the output above for errors.
)
pause
