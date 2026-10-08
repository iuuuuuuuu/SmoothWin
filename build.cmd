@echo off
setlocal
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo [x] csc.exe not found - .NET Framework 4.x is required
  exit /b 1
)
echo [*] compiler: %CSC%
"%CSC%" /nologo /target:winexe /optimize+ /platform:anycpu /codepage:65001 /out:SmoothWinTray.exe SmoothWinTray.cs
if errorlevel 1 (
  echo [x] build failed
  exit /b 1
)
echo [ok] SmoothWinTray.exe
for %%F in (SmoothWinTray.exe) do echo      size: %%~zF bytes
certutil -hashfile SmoothWinTray.exe SHA256 | findstr /r /v "SHA256 CertUtil"
endlocal
