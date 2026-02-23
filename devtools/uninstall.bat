@ECHO OFF

REM Get current directory name
for %%* in (..) do set "PKG_NAME=%%~nx*"

echo uninstalling package: %PKG_NAME%
pip uninstall -y %PKG_NAME%
pause