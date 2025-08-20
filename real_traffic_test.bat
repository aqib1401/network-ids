@echo off
echo ========================================
echo Real Traffic Test
echo ========================================
echo.
echo This will generate REAL network traffic
echo that should be visible on your interface.
echo.
echo Make sure the NIDS is running and capturing!
echo.
pause

echo.
echo [1/3] Pinging Google (ICMP traffic)...
ping -n 10 8.8.8.8

echo.
echo [2/3] DNS lookups...
nslookup google.com
nslookup facebook.com
nslookup youtube.com

echo.
echo [3/3] HTTP requests (if curl is available)...
where curl >nul 2>&1
if %errorLevel% == 0 (
    curl -I https://www.google.com
    curl -I https://www.github.com
) else (
    echo curl not found, skipping HTTP tests
)

echo.
echo ========================================
echo Traffic generation complete!
echo Check your NIDS dashboard now.
echo ========================================
pause
