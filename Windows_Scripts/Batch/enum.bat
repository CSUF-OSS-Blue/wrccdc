@echo off
:: Enumerate processes running on Windows 7 or Vista

:: Display a message
echo Enumerating running processes on your system...
echo.

:: Save all running processes to a file
echo Listing all running processes:
tasklist > RunningProcesses.txt
echo All running processes saved to RunningProcesses.txt
echo.

:: Filter out system processes and save user-level processes
echo Filtering user-level processes (non-system processes):
tasklist | find /V "System Idle Process" | find /V "N/A" > UserProcesses.txt
echo User-level processes saved to UserProcesses.txt
echo.

:: Optional: Count the number of running processes
echo Counting total processes:
for /f %%A in ('tasklist ^| find /C "Image Name"') do set ProcessCount=%%A
echo Total number of running processes: %ProcessCount%
echo.

:: End of the script
echo Process enumeration completed. Output saved to files.
pause
