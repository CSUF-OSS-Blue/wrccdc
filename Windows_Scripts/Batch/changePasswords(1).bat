:: Grab all valid users from the directory and resets the password

@echo off
SET Users="dir C:\Users\ /B"

:: Enable delayed expansion, meaning the variable can continually update between iterations rather than resetting
:: A.K.A makes VARs in loop not act like Python
setlocal enableDelayedExpansion

::==================================================
::                    VARIABLES
::==================================================

:: Characters that can be used to generate passwords
set "alpha=@ # ^& % a A b B c C d D E e f F g G h H I I j J k K l L m M n N p P q Q r R s S t T u U v V w W x X y Y z Z 0 1 2 3 4 5 6 7 8 9"
set "count=0"
set "Password="


::==================================================
::                      MAIN
::==================================================


echo ==================================================
echo.
echo PROGRAM_NAME:%~nx0 Start
echo.
echo ==================================================
echo.
call:checkAdmin
echo.
echo --------------------------------------------------

call:countAlpha

FOR /F "tokens=1*" %%A IN ('%Users%') DO (
	SET "Name=%%A"
	SET "valid="
	:: Check the user is not Admin, Public, or the Current User
	call:isValid !NAME! valid
	IF !VALID! == true (
		echo Changing !NAME!'s password:
		echo.
				
		call:generatePassword Password
				
		:: Change the user's password
		net user !NAME! !PASSWORD!
				
		:: Echo so we can see what the new password is :)
		echo !NAME!'s password is now: !PASSWORD!
				
	) ELSE (
		echo !NAME!'s password cannot be changed
	)
	echo.
	echo --------------------------------------------------
	echo.
)

:programEnd
echo ==================================================
echo.
echo PROGRAM_NAME:%~nx0 End 
echo.
echo ==================================================
echo.&goto:eof



::==================================================
::                    FUNCTIONS
::==================================================

:checkAdmin
	echo Administrative permissions required. Detecting permissions...
    
	net session >nul 2>&1
	IF %errorLevel% == 0 (
		echo Success: Administrative permissions confirmed.
	) ELSE (
		echo Failure: Current permissions inadequate.
		goto:programEnd
	)
goto:eof


:countAlpha
	:: Counts how many characters are in alpha and creates an array of valid characters to pull from
	for %%a in (%alpha%) do (
		set "rn.!count!=%%a"
		set /a "count+=1"
	)
goto:eof

:isValid <username> <valid>
	SET "validName=%~1"
	SET "%~2=false"
	:: Check the user is not Admin, Public, or the Current User
	IF /I "!validName!" NEQ "%USERNAME%" (
		IF /I "!validName!" NEQ "Administrator" (
			IF /I "!validName!" NEQ "Public" (
				SET "%~2=true"
			)
		)
	)
goto:eof

:generatePassword <passwordVariable>
	:: Generate Password of length 16
	set "pssw="
	for /l %%a in (1,1,16) do (
		set /a "rand=!random! %% count"
		for %%b in (!rand!) do set "pssw=!pssw!!rn.%%b!"
	)
	echo Password created: !pssw!
	set %~1=!pssw!
goto:eof
