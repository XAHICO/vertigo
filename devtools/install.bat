@ECHO OFF

REM Get current directory name
for %%* in (..) do set "PKG_NAME=%%~nx*"

echo installing package: %PKG_NAME%

pip install -e ..

pause