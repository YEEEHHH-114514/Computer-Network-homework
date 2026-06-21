@echo off
cd /d "%~dp0"

echo ========================================
echo   Network Traffic Analysis Tool
echo ========================================
echo.

REM --- Find pcap file ---
set PCAP_DIR=captures
set PCAP_FILE=

for %%f in ("%PCAP_DIR%\*.pcapng" "%PCAP_DIR%\*.pcap" "%PCAP_DIR%\*.pcapng.gz") do (
    if exist "%%f" (
        set "PCAP_FILE=%%f"
        goto :found
    )
)

echo [ERROR] No pcap file found in captures\ directory!
echo         Please put your capture file into captures\ and retry.
pause
exit /b 1

:found
echo [OK]   Data file: %PCAP_FILE%
echo.

REM --- Local IP ---
echo.
set /p LOCAL_IP="Enter your local IP address: "
if "%LOCAL_IP%"=="" (
    echo [ERROR] No IP address entered.
    pause
    exit /b 1
)
echo.
echo       Local IP: %LOCAL_IP%
echo.

REM --- Maven path ---
set MVN=%USERPROFILE%\apache-maven-3.9.16\bin\mvn.cmd
if not exist "%MVN%" (
    echo [ERROR] Maven not found at %MVN%
    echo         Please update MAVEN_HOME in this script.
    pause
    exit /b 1
)

REM --- Compile ---
echo [1/3] Compiling...
call "%MVN%" clean compile -q
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Compilation error, check messages above.
    pause
    exit /b 1
)
echo       Build OK!
echo.

REM --- Run ---
echo [2/3] Running analyzer...
call "%MVN%" exec:java -q -Dexec.mainClass="com.network.Main" -Dexec.args="%PCAP_FILE% %LOCAL_IP%"
if %ERRORLEVEL% neq 0 (
    echo [FAIL] Runtime error, check messages above.
    pause
    exit /b 1
)
echo.

REM --- Open report ---
echo [3/3] Opening report...
if exist "output\report.html" (
    start "" "output\report.html"
    echo       Browser opened: output\report.html
) else (
    echo [WARN] output\report.html was not generated
)
echo.
echo ========================================
echo   Done!
echo ========================================
pause
