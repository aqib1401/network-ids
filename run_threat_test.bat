@echo off
echo ========================================
echo NIDS Threat Generator
echo ========================================
echo.
echo This will generate attack traffic to test the NIDS.
echo Make sure the NIDS is running and capturing on WiFi!
echo.
pause

python threat_generator.py

pause
