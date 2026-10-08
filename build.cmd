@echo off
setlocal
chcp 65001 >nul
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo [x] 找不到 csc.exe，请确认系统已安装 .NET Framework 4.x
  exit /b 1
)
echo [*] 编译器: %CSC%
"%CSC%" /nologo /target:winexe /optimize+ /platform:anycpu /codepage:65001 /out:SmoothWinTray.exe SmoothWinTray.cs
if errorlevel 1 (
  echo [x] 编译失败
  exit /b 1
)
echo [ok] 已生成 SmoothWinTray.exe
for %%F in (SmoothWinTray.exe) do echo     大小: %%~zF 字节
certutil -hashfile SmoothWinTray.exe SHA256 | findstr /r /v "SHA256 CertUtil"
endlocal
