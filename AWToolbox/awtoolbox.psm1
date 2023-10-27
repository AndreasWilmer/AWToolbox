<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2021 v5.8.187
	 Created on:   	27/10/2023 23:31
	 Created by:   	Andreas Wilmer
	 Organization: 	AWILMER
	 Filename:     	AWToolbox.psm1
	-------------------------------------------------------------------------
	 Module Name: 	AWToolbox
	===========================================================================
#>

#region Logging
#region LoggingParameters
Function Set-DefaultLogPath {
	<#
	.SYNOPSIS
		Sets an enviroment variable for a LogPath
	.DESCRIPTION
		Sets a new enviroment machine variable (LogPath) to specify the default path of the logs.
	.PARAMETER Logpath
		This parameter defines the location of the log files.
	.EXAMPLE
		Set-DefaultLogpath -Logpath 'Value1'
#>
	[CmdletBinding(SupportsShouldProcess)]
	Param
	(
		[Parameter(Mandatory = $false, Position = 0)][String]$LogPath
	)
	If ([String]::IsNullOrEmpty($LogPath)) {
		$LogPath = $null = Read-Host -Prompt "You dont have a default LogPath set, enter one or leave the input empty to make C:\Scripts_Logs as the default location for script files."
		If ([String]::IsNullOrEmpty($LogPath)) {
			$LogPath = 'C:\Scripts_Logs'
		}
		if ($PSCmdlet.ShouldProcess('EnvironmentVariable - Machine', 'Set LogPath variable and Value')) {
			[Environment]::SetEnvironmentVariable('LogPath', "$($LogPath)", 'Machine')
		}
		$Env:LogPath = $LogPath
	}
	Else {
		if ($PSCmdlet.ShouldProcess('EnvironmentVariable - Machine', 'Set LogPath variable and Value')) {
			[Environment]::SetEnvironmentVariable('LogPath', "$($LogPath)", 'Machine')
		}
		$Env:LogPath = $LogPath
	}
	$WriteLogCSVCommonParamsHash, $WriteLogCSVErrorParamsHash, $WriteLogCSVErrorsHash, $WriteLogCSVNoticeParamsHash, $WriteLogCSVWarningParamsHash = Get-DefaultLoggingParameters -FunctionNameStr ($MyInvocation.MyCommand).name -Module ($PSCommandPath).split("\")[-1].split(".")[0]
	$WriteLogCSVNoticeParamsHash.Consoleoutput = $True
	write-LogCSV -text "Set default LoggPath to $($env:logpath)" @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
}
Function Get-DefaultLoggingParameters {
	<#
	.SYNOPSIS
		Returns the Default Parametersets for the Write-LogCsv function
	.DESCRIPTION
		returns the Parameters in the order:
		$WriteLogCSVCommonParamsHash,$WriteLogCSVErrorParamsHash,$WriteLogCSVErrorsHash,$WriteLogCSVNoticeParamsHash,$WriteLogCSVWarningParamsHash
	.PARAMETER FunctionNameStr
		A description of the FunctionNameStr parameter.
	.PARAMETER Module
		A description of the Module parameter.
	.EXAMPLE
		Get-DefaultLoggingParameters -FunctionNameStr 'Value1' -Module 'Value2'
	.EXAMPLE
		$WriteLogCSVCommonParamsHash, $WriteLogCSVErrorParamsHash, $WriteLogCSVErrorsHash, $WriteLogCSVNoticeParamsHash, $WriteLogCSVWarningParamsHash = Get-DefaultLoggingParameters -FunctionNameStr 'Value1' -Module 'Value2'
	.OUTPUTS
		Variables with parameters in it: $WriteLogCSVCommonParamsHash, $WriteLogCSVErrorParamsHash, $WriteLogCSVErrorsHash, $WriteLogCSVNoticeParamsHash, $WriteLogCSVWarningParamsHash
#>
	
	[CmdletBinding()][OutputType([System.Object[]])]
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)][string]$FunctionNameStr,
		[Parameter(Mandatory = $true, Position = 1)][string]$Module,
		[Parameter(Mandatory = $false, Position = 2)][ValidateSet('error', 'errors', 'notice', 'warning', 'pending')][string[]]$OptOutput
	)
	If ([String]::IsNullOrEmpty($Env:Logpath)) {
		If ((Get-CimInstance Win32_OperatingSystem).caption -match 'Server') {
			Set-DefaultLogpath
		}
		Else {
			$Env:LogPath = 'C:\Scripts_Logs'
		}
	}
	$WriteLogCSVCommonParamsHash = $null = @{
		Filename = "$($FunctionNameStr)_$($env:USERNAME)_$((get-date -format o).replace(":", ".").replace("+", ".")).csv"
		Filepath = "$($Env:Logpath)\$($Module)\$($FunctionNameStr)";
	}
	$WriteLogCSVNoticeParamsHash = $null = @{
		LogType	  = "Notice";
		consoleOutput = $false;
	}
	$WriteLogCSVWarningParamsHash = $null = @{
		LogType	  = "Warning";
		consoleOutput = $false;
	}
	$WriteLogCSVErrorParamsHash = $null = @{
		LogType	  = "Error";
		consoleOutput = $false;
	}
	$WriteLogCSVErrorsHash = $null = @{
		LogType	  = "Error";
		consoleOutput = $false;
	}
	$WriteLogCSVPendingParamsHash = $null = @{
		LogType	  = "Pending";
		consoleOutput = $false;
	}
	switch ($OptOutput) {
		"error" 	{
			$WriteLogCSVErrorParamsHash.consoleOutput = $true
		}
		"errors"  	{
			$WriteLogCSVErrorsHash.consoleOutput = $true
		}
		"notice"  	{
			$WriteLogCSVNoticeParamsHash.consoleOutput = $true
		}
		"warning" 	{
			$WriteLogCSVWarningParamsHash.consoleOutput = $true
		}
		"pending" 	{
			$WriteLogCSVPendingParamsHash.consoleOutput = $true
		}
	}
	Return $WriteLogCSVCommonParamsHash, $WriteLogCSVErrorParamsHash, $WriteLogCSVErrorsHash, $WriteLogCSVNoticeParamsHash, $WriteLogCSVWarningParamsHash
}
#endregion LoggingParameters
Function write-LogTXT {
	<#
	.SYNOPSIS
		Writes to a specified Logfile the given Input.
	.DESCRIPTION
		Writes to a specified Logfile the given Input.
	.PARAMETER Text
		Value that should be written in the log.
	.PARAMETER LogType
		Type of the log Entry only allowed "error", "notice", "warning"
	.PARAMETER ConsoleOutput
		Switch if the input should also be writen to the console
	.PARAMETER NoInfo
		Supressing info [Type]UTCTime...
	.PARAMETER DividerPosition
		Switch if the next line or previus one should be a dividing element (A line full of # will be generatet)
	.PARAMETER Filepath
		The path where log is stored. Default is userprofile path
	.PARAMETER FileName
		Name of the Logfile. Default is Lofile_yyy_mmm_dd.txt
	.EXAMPLE
		write-LogTXT -Text "LogfileText" -LogType error -ConsoleOutput -filepath c:\temp -filename "Logfile.txt"
	.EXAMPLE
		write-LogTXT -Text "LogfileText" -LogType error -ConsoleOutput
	.OUTPUTS
	    	Logfile
		$ENV:LogFilePath is set to the filepath of the Written Logfile.
#>
	param
	(
		[Parameter(Mandatory = $true, Position = 0)][string]$text,
		[Parameter(Mandatory = $true)][ValidateSet('error', 'notice', 'warning')][string]$logType,
		[Parameter(Mandatory = $false)][switch]$consoleOutput,
		[Parameter(Mandatory = $false)][switch]$NoInfo,
		[Parameter(Mandatory = $false)][ValidateSet('Top', 'Bottom')][string]$DividerPosition,
		[Parameter(Mandatory = $false)][string]$filePath = $env:USERPROFILE,
		[Parameter(Mandatory = $false)][string]$fileName = "Logfile_$(get-date -format yyyy_MM_dd).txt"
	)
	
	#Initial Clearing of all variables
	$fileFullName = $null
	$output = $null
	$background = $null
	$foreground = $null
	$fileFullName = "$($FilePath)\$($filename)"
	If ($DividerPosition -eq "Top") {
		$output = "##########################################################################################################################################################################################"
		$output | Out-File -FilePath $fileFullName -Append
	}
	If ($NoInfo -ne $true) {
		$output = "[$($logType.toUpper())] $(get-date ((get-date).ToUniversalTime()) -format o) $($text)"
	}
	ElseIf ($NoInfo -eq $true) {
		$output = "$($text)"
	}
	Switch ($logType) {
		"error" {
			$background = "red"
			$foreground = "white"
		}
		"notice" {
			$background = "green"
			$foreground = "black"
		}
		"warning" {
			$background = "yellow"
			$foreground = "black"
		}
	}
	If ($consoleoutput) {
		$output | Out-File -FilePath $fileFullName -Append
		write-host $output -foregroundcolor $foreground -backgroundcolor $background
	}
	Else {
		$output | Out-File -FilePath $fileFullName -Append
	}
	If ($DividerPosition -eq "Bottom") {
		$output = "##########################################################################################################################################################################################"
		$output | Out-File -FilePath $fileFullName -Append
	}
	$ENV:LogFilePath = $fileFullName
}
Function write-LogCSV {
    <#
    .SYNOPSIS
    	Writes to a specified Logfile the given input.
    .DESCRIPTION
    	Writes to a specified Logfile the given input.
    .EXAMPLE
    	write-LogCSV -Text "LogfileText" -objectName "NameOfTheObject" -objectNameSecondary "Secondary name of the Object" -LogType error -ConsoleOutput -filepath c:\temp -filename "Logfile.csv"
    .EXAMPLE
    	"LogFileText | write-LogCSV -LogType error -ConsoleOutput
    .EXAMPLE
    	write-LogCSV -Text "LogfileText" -objectName "NameOfTheObject" -objectNameSecondary "Secondary name of the Object" -LogType notice
    .PARAMETER Text
    	Value that should be written in the log.
   .PARAMETER LogType
    	Type of the log Entry only allowed "error", "notice", "warning","pending"
    .PARAMETER ConsoleOutput
    	Switch if the input should also be writen to the console
    .PARAMETER DividerPosition
    	Switch if the next line or previus one should be a dividing element (A line full of # will be generatet)
    .PARAMETER ScriptStart
    	Add CSV Header infront of output row
    .PARAMETER Separator
    	Define the separator for the file only allowed "," and ";" - Default is semicolon ";"
    .PARAMETER ObjectName
    	Add ObjectName in separation
    .PARAMETER ObjectNameSecondary
    	Add ObjectNameSecondary in separation
    .PARAMETER Filepath
    	The path where log is stored. Default is userprofile path
    .PARAMETER FileName
    	Name of the Logfile. Default is Logfile_yyy_mmm_dd.txt
    .OUTPUTS
	Logfile
    	$ENV:LogFilePath is set to the filepath of the Written Logfile.
   #>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline, Position = 0)][string]$text,
		[Parameter(Mandatory = $true)][ValidateSet("error", "notice", "warning", "pending")][string]$logType,
		[Parameter(Mandatory = $false)][string]$ObjectName = "",
		[Parameter(Mandatory = $false)][string]$ObjectNameSecondary = "",
		[Parameter(Mandatory = $false)][ValidateSet(";", ",")][string]$Separator = ";",
		[Parameter(Mandatory = $false)][switch]$consoleOutput,
		[Parameter(Mandatory = $false)][string]$filePath = $Env:LogPath,
		[Parameter(Mandatory = $false)][string]$fileName = "$($env:username)_Logfile_$(get-date -format yyyy_MM_dd).csv"
	)
	Begin {
		#Initial Clearing of all variables
		$fileFullName = $null
		$output = $null
		$background = $null
		$foreground = $null
		If ([String]::IsNullOrEmpty($filePath)) {
			Set-DefaultLogpath
			$filePath = $Env:LogPath
		}
		If (!(Test-Path -Path $FilePath)) {
			new-item $filepath -ItemType Directory | Out-Null
		}
		$fileFullName = "$($FilePath)\$($filename)"
		If (!(Test-Path -Path $fileFullName)) {
			"LogType$($separator)TimeStamp$($separator)LogText$($separator)ObjectName$($separator)ObjectNameSecondary" | Out-File -FilePath $fileFullName -Append -Encoding utf8
		}
	}
	Process {
		
		$output = "[$($logType.toUpper())]$($separator)$(get-date ((get-date).ToUniversalTime()) -format o)$($separator)$($text)$($separator)$($objectname)$($separator)$($objectnamesecondary)"
		Switch ($logType) {
			"error" {
				$background = "red"
				$foreground = "white"
			}
			"notice" {
				$background = "green"
				$foreground = "black"
			}
			"warning" {
				$background = "yellow"
				$foreground = "black"
			}
			"pending" {
				$background = "Magenta"
				$foreground = "white"
			}
		}
		If ($consoleOutput) {
			$output | Out-File -FilePath $fileFullName -Append -Encoding utf8
			write-host $output.replace($($separator), " ") -foregroundcolor $foreground -backgroundcolor $background
			write-verbose $output.replace($($separator), " ")
			write-debug $output.replace($($separator), " ")
		}
		Else {
			$output | Out-File -FilePath $fileFullName -Append -Encoding utf8
			write-verbose $output.replace($($separator), " ")
			write-debug $output.replace($($separator), " ")
		}
		
	}
	End {
		$ENV:LogFilePath = $fileFullName
	}
}
#endregion Logging
#region progress
Function add-ProgressBar {
    <#
    .SYNOPSIS
    	Displays a Progressbar
    .DESCRIPTION
    	Displays a progressbar with the given Activity and the correct Percentage value
    .EXAMPLE
    	add-progressBar -totalCount 1345 -momentualCount 5
    .EXAMPLE
    	add-progressBar -totalCount 1345 -momentualCount 5 -activity -status -currentOperation
    .PARAMETER totalCount
    	the total Amount of Operations that have to be performed
    .PARAMETER momentualCount
    	the number of the operation that is currently performed
    .PARAMETER activity
    	Description of what is Performed. Default is "Processing"
    .PARAMETER status
    	Status of the general progress. Default is momentualCount"/"totalCount:
    .PARAMETER currentOperration
    	The current operation that is performed. I.E. WHat Object is currently being processed.
    .OUTPUTS
    	momentualCount accelerated by one
	#>
	Param (
		[Parameter(Mandatory = $true, Position = 0)][int]$totalCount,
		[Parameter(Mandatory = $true, Position = 1)][int]$momentualCount,
		[Parameter(Mandatory = $false, Position = 2)][string]$activity = "Processing",
		[Parameter(Mandatory = $false, Position = 3)][string]$status = "$($momentualCount)/$($totalCount)",
		[Parameter(Mandatory = $false, Position = 4)][string]$currentOperation = ""
	)
	[int]$percentage = ($momentualCount/$totalCount * 100)
	Write-Progress -Activity $activity -Status "$($status): $($percentage)%" -CurrentOperation $currentOperation -PercentComplete $percentage
	$momentualCount = $momentualCount + 1
	Return $momentualCount
}
#endregion progress
#region countdown
Function New-VisualSleepCountdown {
    <#
    .SYNOPSIS
    	This function will display a countdown progressbar
    .DESCRIPTION
    	This function will display a countdown progressbar
    .EXAMPLE
    	New-VisualSleepCountdown -seconds 10
    .PARAMETER seconds
    	This parameter defines the number of seconds that the countdown will run
    .OUTPUTS
    	Progressbar for seconds
    #>
	[CmdletBinding(SupportsShouldProcess)]
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)][int]$seconds
	)
	if ($PSCmdlet.ShouldProcess('PowerShell Console', "New-VisualSleepCountdown for $($seconds) seconds")) {
		[int]$Count = 0
		Do {
			Write-Progress -Activity "Wait until completed ($($seconds)) seconds" -Status "$($seconds - $Count) seconds left" -PercentComplete ($count/$seconds * 100)
			Start-Sleep -Seconds 1
			$Count++
		}
		Until ($Count -eq $seconds)
	}
	
}
#endregion countdown
#region output
function out-gridLogCSV {
<#
	.SYNOPSIS
		Calls the out-GridView function for the specified file
	.DESCRIPTION
		Calls the out-GridView function for the specified file with the correct delimiter and formating
	.PARAMETER Filepath
		The path where log is stored. Default is userprofile path
	.PARAMETER FileName
		Name of the Logfile. Default is Lofile_yyy_mmm_dd.txt
	.PARAMETER output
		A Switch that is default set to false, if you set it then you can click something in the grid Window and it will be returned by the function
	.PARAMETER Delimiter
		you can specify the delimiter of the logfile. Default is ";"
	.PARAMETER FileFullPath
		A description of the FileFullPath parameter.
	.EXAMPLE
		out-GridLogCSV -filepath c:\temp -filename "Logfile.csv"
	.EXAMPLE
		out-GridLogCSV
	.OUTPUTS
		If the output Switch is set then the marked columns in the Gridview are returned
#>
	
	param
	(
		[Parameter(ParameterSetName = 'FileName', Mandatory = $true, Position = 0)][string]$filePath = "C:\Scripts_Logs\LoggingToolbox",
		[Parameter(ParameterSetName = 'FileName', Mandatory = $true, Position = 1)][string]$fileName = "$($env:username)_Logfile_$(get-date -format yyyy_MM_dd).csv",
		[Parameter(ParameterSetName = 'FileFullName', Mandatory = $true, Position = 0)][string]$fileFullName,
		[Parameter(ParameterSetName = 'FileName', Mandatory = $false, Position = 2)][Parameter(ParameterSetName = 'FileFullName', Position = 1)][switch]$output,
		[Parameter(ParameterSetName = 'FileName', Mandatory = $false, Position = 3)][Parameter(ParameterSetName = 'FileFullName', Position = 2)][string]$delimiter = ";"
	)
	switch ($PsCmdlet.ParameterSetName) {
		'FileName'{
			$fileFullName = $null
			$fileFullName = "$($FilePath)\$($filename)"
		}
		'fileFullName'{
			continue
		}
	}
	
	if ((Test-Path -Path $fileFullName) -and ($fileFullName.EndsWith(".csv"))) {
		$logCSV = Import-Csv -Path $fileFullName -Delimiter $delimiter -Encoding UTF8
		if ($output) {
			$Env:outGridLogCSVReturn = $logCSV | Out-GridView -Title "$($fileName)" -PassThru
			return $Env:outGridLogCSVReturn
		}
		else {
			$logCSV | Out-GridView -Title "$($fileName)" -Wait
		}
	}
	else {
		write-host "[ERROR] File $($fileFullName) does not Exists or is not a .csv" -ForegroundColor "white" -backgroundcolor "red"
	}
}
#endregion Logging

#region Password creation
Function New-Password {
	<#
	.SYNOPSIS
		This function will create a secure password .	
	.DESCRIPTION
		This function will create a secure password.
		The Dictionary will be loaded from https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt 	
		ASCII characters used
		65-90  (A-Z)
		97-122 (a-z)
		33-38  (!"#$%&)
		40-57  (()*+,-./0-9)
		64     (@)
	.PARAMETER Length
		Specifies the number of characters for the password	
	.PARAMETER Words
		Specifies the number of words used as a password, joined with "-"	
	.PARAMETER CopyToClipboard
		This Parameter will copy the new password to the clipboard
	.PARAMETER SpecialCharacters
		Specifies the number of special characters in a password. Default Value is 4	
	.PARAMETER Numbers
		Specifies the number of numbers in a password. Default Value is 2	
	.EXAMPLE
		new-password -Length 10
		x}[xz).1g{	
	.EXAMPLE
		new-password -length 10 -CopyToClipboard
		x}[xz).1g{	
	.EXAMPLE
		new-password -Length 20 -SpecialCharacters 2 -Numbers 3
		zTt!DKy0rLE.Pg6sm5Yd		
	.EXAMPLE
		new-password -Words 4
		Outsigh-Simarouba-Cockle-Holometer	
#>
	
	Param
	(
		[Parameter(ParameterSetName = 'characters', Mandatory = $true, Position = 0)][INT]$Length,
		[Parameter(ParameterSetName = 'words', Mandatory = $true, Position = 0)][INT]$Words,
		[Parameter(ParameterSetName = 'words', Mandatory = $false)][Parameter(ParameterSetName = 'characters')][switch]$CopyToClipboard,
		[Parameter(ParameterSetName = 'characters')][int]$SpecialCharacters = 4,
		[Parameter(ParameterSetName = 'characters')][int]$Numbers = 2
	)
	$Global:NewPassword = $null
	If ($length) {
		$ToRandomize = @()
		$ToRandomize += ((33 .. 38) + (40 .. 47) + (64) | Get-Random -Count $SpecialCharacters | ForEach-Object {
				[char]$_
			})
		$ToRandomize += -join ((48 .. 57) | Get-Random -Count $numbers | ForEach-Object {
				[char]$_
			})
		$ToRandomize += ((65 .. 90) + (97 .. 122) | Get-Random -Count ($length - ($SpecialCharacters + $numbers)) | ForEach-Object {
				[char]$_
			})
		$Global:NewPassword = ($torandomize | Sort-Object {
				get-random
			}) -join ""
	}
	If ($words) {
		$temp = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt').content.Split([Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries);
		$Global:NewPassword = (get-random -InputObject $temp -count $words | ForEach-Object{
				$_.substring(0, 1).toupper() + $_.substring(1)
			}) -join "-"
	}
	If ($CopyToClipboard) {
		$Global:NewPassword | clip
	}
	Return $Global:NewPassword
}
#endregion Password creation

#region Exchange
Function disable-MailboxAutomapping {
	<# 
    .SYNOPSIS 
    	removes automapping for all permitted users of a mailbox
    .DESCRIPTION 
    	removes automapping for all permitted users of a mailbox
    .EXAMPLE 
    	disable-mailboxautomapping -racf MUST11
    .EXAMPLE 
    	disable-mailboxautomapping -racf MUST11 -SelectedUser
    .PARAMETER RACF 
    	RACF ID 
    .PARAMETER SelectedUser
    	Starts OutGridView to select multiple users for removing Automapping (FullAccess permission only)
#>	
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)][String]$RACF,
		[Parameter(Mandatory = $false, Position = 1)][switch]$SelectedUser
	)
	import-module loggingtoolbox
	
	test-EXOConnection
	$WriteLogCSVCommonParamsHash, $WriteLogCSVErrorParamsHash, $WriteLogCSVErrorsHash, $WriteLogCSVNoticeParamsHash, $WriteLogCSVWarningParamsHash = Get-DefaultLoggingParameters -FunctionNameStr ($MyInvocation.MyCommand).name -Module ($PSCommandPath).split("\")[-1].split(".")[0]
	If ($connection) {
		If ($SelectedUser) {
			get-M365mailbox -identity $racf -erroraction Stop
			$permission = $null = get-M365mailboxpermission -Identity $RACF
			$removal = $permission | select-object user, accessrights | where-object {
				$psitem.accessrights -match "FullAccess"
			} | Out-GridView -Title "AccessRights - select multiple to remove automount" -OutputMode Multiple
			ForEach ($object In $removal) {
				Try {
					Remove-M365MailboxPermission -Identity $RACF -user $object.user -accessrights "FullAccess" -confirm:$False
					Add-M365MailboxPermission -Identity $RACF -user $object.user -accessrights "FullAccess" -automapping:$False -confirm:$False
					write-LogCSV -Text "Automapping for user $($object.user) removed successfully from Mailbox $($RACF)" -objectName $RACF -ObjectNameSecondary $object.user @WriteLogCSVNoticeParamsHash @WriteLogCSVCommonParamsHash
				}
				Catch {
					write-LogCSV -Text "Automapping removing failed for user $($object.user) from Mailbox $($RACF)" -objectName $RACF -ObjectNameSecondary $object.user @WriteLogCSVErrorParamsHash @WriteLogCSVCommonParamsHash
					write-LogCSV -text "$($error[0].exception) " @WriteLogCSVErrorsHash @WriteLogCSVCommonParamsHash -objectName $RACF
				}
			}
		}
		Else {
			Try {
				get-M365mailbox -identity $racf -erroraction Stop
				Remove-M365MailboxPermission -Identity $RACF -ClearAutoMapping -Confirm:$False
				write-LogCSV -Text "Automapping removed successfully from Mailbox $($RACF)" -objectName $RACF  @WriteLogCSVNoticeParamsHash @WriteLogCSVCommonParamsHash
				
			}
			Catch {
				write-LogCSV -Text "Automapping removing failed from Mailbox $($RACF)" -objectName $RACF @WriteLogCSVErrorParamsHash @WriteLogCSVCommonParamsHash
				write-LogCSV -text "$($error[0].exception) " @WriteLogCSVErrorsHash @WriteLogCSVCommonParamsHash -objectName $RACF
				
			}
		}
	}
	Else {
		write-LogCSV -text "Function aborted because of missing ExchangeOnline Connection" @WriteLogCSVErrorParamsHash @WriteLogCSVCommonParamsHash
	}
}
Function Set-MailboxDefaultFolderPermissions {
	<# 
    .SYNOPSIS 
		Set default folder permissions for all folders in a mailbox
    .DESCRIPTION
		Set default folder permissions for all folders in a mailbox
    .EXAMPLE 
		Set-MailboxDefaultFolderPermissions -Mailbox "MUST123@domain.com"
    .EXAMPLE 
		Set-MailboxDefaultFolderPermissions -Mailbox "MUST123@domain.com","MUST234@domain.com"
    .PARAMETER Mailbox [Array]
		Primary SMTP Address of a mailbox
#>	
	Param (
		[Parameter(Mandatory = $true, Position = 0)][string[]]$mailbox
	)
	import-module loggingtoolbox
	test-EXOConnection
	$WriteLogCSVCommonParamsHash, $WriteLogCSVErrorParamsHash, $WriteLogCSVErrorsHash, $WriteLogCSVNoticeParamsHash, $WriteLogCSVWarningParamsHash = Get-DefaultLoggingParameters -FunctionNameStr ($MyInvocation.MyCommand).name -Module ($PSCommandPath).split("\")[-1].split(".")[0]
	If ($connection) {
		ForEach ($Item In $mailbox) {
			write-LogCSV "MailboxFolderPermission - Mailbox: $($Item)  -- START" @WriteLogCSVNoticeParamsHash @WriteLogCSVCommonParamsHash -objectName $item
			$MailboxFolderList = $null = Get-M365MailboxFolderStatistics -Identity $Item
			$MailboxFolderReport = @()
			ForEach ($Folder In $MailboxFolderList) {
				$ID = $null = "$($folder.identity.split('\')[0]):\$($folder.identity.split('\')[1])"
				$Permissions = $null = Get-M365MailboxFolderPermission -Identity $ID
				ForEach ($permission In $Permissions) {
					$obj = new-object psobject -Property @{
						ID   = $ID
						User = [string]$Permission.user
						Permission = [string]$Permission.AccessRights
					}
					$MailboxFolderReport += $Obj
					$Obj = $null
				}
			}
			write-LogCSV "Start processing MailboxPermissions - Mailbox: $($Item)" @WriteLogCSVNoticeParamsHash @WriteLogCSVCommonParamsHash -objectName $item
			$FilteredList = $MailboxFolderReport | Where-Object {
				(($psitem.user -ne "Anonymous") -and ($psitem.user -ne "Default"))
			}
			ForEach ($FilteredItem In $FilteredList) {
				Try {
					Remove-M365MailboxFolderPermission -Identity ($FilteredItem.id) -user ($FilteredItem.user) -Confirm:$false
					write-LogCSV "successfully removed $($FilteredItem.id) Permission for $($FilteredItem.user)" @WriteLogCSVNoticeParamsHash @WriteLogCSVCommonParamsHash -objectName $FilteredItem.id -objectNameSecondary $FilteredItem.user
				}
				Catch {
					write-LogCSV "failed to remove $($FilteredItem.id) Permission for $($FilteredItem.user)" @WriteLogCSVErrorParamsHash @WriteLogCSVCommonParamsHash -objectName $FilteredItem.id -objectNameSecondary $FilteredItem.user
					write-LogCSV -text "$($psitem.exception) " @WriteLogCSVErrorsHash @WriteLogCSVCommonParamsHash -objectName $FilteredItem.id -objectNameSecondary $FilteredItem.user
				}
			}
			write-LogCSV "MailboxFolderPermission - Mailbox: $($Item)  -- END"  @WriteLogCSVNoticeParamsHash @WriteLogCSVCommonParamsHash
		}
	}
	Else {
		write-LogCSV -text "Function aborted because of missing ExchangeOnline Connection" @WriteLogCSVErrorParamsHash @WriteLogCSVCommonParamsHash
	}
}
Function Get-MailboxAllFolderPermissions {
	<# 
    .SYNOPSIS 
		Set default folder permissions for all folders in a mailbox
    .DESCRIPTION
		Set default folder permissions for all folders in a mailbox
    .EXAMPLE 
		Get-MailboxAllFolderPermissions -Mailbox "MUST123@domain.com"
    .EXAMPLE 
		Get-MailboxAllFolderPermissions -Mailbox "MUST123@domain.com","MUST234@domain.com"
    .PARAMETER Mailbox [Array]
		Primary SMTP Address of a mailbox
    .OUTPUTS
    		Logfile
#>	
	Param (
		[Parameter(Mandatory = $true, Position = 0)][string[]]$mailbox
	)
	import-module loggingtoolbox
	test-EXOConnection
	$WriteLogCSVCommonParamsHash, $WriteLogCSVErrorParamsHash, $WriteLogCSVErrorsHash, $WriteLogCSVNoticeParamsHash, $WriteLogCSVWarningParamsHash = Get-DefaultLoggingParameters -FunctionNameStr ($MyInvocation.MyCommand).name -Module ($PSCommandPath).split("\")[-1].split(".")[0]
	If ($connection) {
		$Global:MailBoxFolderPermissionReport = $null = @()
		ForEach ($Item In $mailbox) {
			write-LogCSV "MailboxFolderPermission - Mailbox: $($Item)  -- START" @WriteLogCSVNoticeParamsHash @WriteLogCSVCommonParamsHash -objectName $item
			$MailboxFolderList = $null = Get-M365MailboxFolderStatistics -Identity $Item
			$MailboxFolderReport = $null = @()
			ForEach ($Folder In $MailboxFolderList) {
				$ID = $null = "$($folder.identity.split('\')[0]):\$($folder.identity.split('\')[1])"
				$Permissions = $null = Get-M365MailboxFolderPermission -Identity $ID
				ForEach ($permission In $Permissions) {
					$Permobj = $null
					$Permobj = new-object psobject -Property @{
						ID   = $ID
						User = [string]$permission.user.displayname
						Permission = [string]$permission.AccessRights
						SharingPermissionFlags = [String]$permission.SharingPermissionFlags
					}
					$MailboxFolderReport += $Permobj
				}
			}
			$Global:MailBoxFolderPermissionReport += $MailboxFolderReport
		}
	}
	Else {
		write-LogCSV -text "Function aborted because of missing ExchangeOnline Connection" @WriteLogCSVErrorParamsHash @WriteLogCSVCommonParamsHash
	}
	$Global:MailBoxFolderPermissionReport | select-object ID, User, Permission, SharingPermissionFlags | sort-object ID, User -Unique
	$Global:MailBoxFolderPermissionReport | select-object ID, User, Permission, SharingPermissionFlags | sort-object ID, User -Unique | export-csv "$($env:LogPath)\CommonToolbox\Get-MailboxAllFolderPermissions\Get-MailboxAllFolderPermissions_Report_$(get-date -format yyyy-MM-dd).csv" -delimiter ";" -NoTypeInformation -Encoding utf8
}
#endregion Exchange
#region Diacritics
function Remove-Diacritics {
    <# 
    .SYNOPSIS 
    This function will remove the diacritics (accents) characters from a string.
    .DESCRIPTION
    This function will remove the diacritics (accents) characters from a string.
    .PARAMETER Text
    Specifies the String on which the diacritics need to be removed
    .PARAMETER Removeblanks
    Replace blanks from string against underscore _
    .EXAMPLE 
    remove-diactritics -text "Änne Mußtermann"

    Aenne Musstermann

    .EXAMPLE 
    remove-diactritics -text "Änne Mußtermann" -removeblanks

    Aenne_Musstermann
	.OUTPUTS
    String with replaces diacritics
    #>	
	param (
		[Parameter(Mandatory = $true, Position = 0)][String]$text,
		[Parameter(Mandatory = $false, Position = 1)][Switch]$RemoveBlanks
	)
	$text = $text.replace("Ä", "Ae").replace("ä", "ae").replace("Ö", "Oe").replace("ö", "oe").replace("Ü", "Ue").replace("ü", "ue")
	$replaceTable = @{
		"ß" = "ss"; "à" = "a"; "á" = "a"; "â" = "a"; "ã" = "a"; "å" = "a"; "æ" = "ae"; "ç" = "c"; "è" = "e"; "é" = "e"; "ê" = "e"; "ë" = "e"; "ì" = "i"; "í" = "i"; "î" = "i"; "ï" = "i"; "ð" = "d"; "ñ" = "n"; "ò" = "o"; "ó" = "o"; "ô" = "o"; "õ" = "o"; "ø" = "o"; "ù" = "u"; "ú" = "u"; "û" = "u"; "ý" = "y"; "þ" = "p"; "ÿ" = "y"
	}
	foreach ($key in $replaceTable.Keys) {
		$text = $text -Replace ($key, $replaceTable.$key)
	}
	if ($removeblanks) {
		$text = $text.ToString().replace(" ", "_")
	}
	return $text
}
function Remove-SpecialCharacters {
	<#
		.SYNOPSIS
			This function will remove the special character from a string.
		
		.DESCRIPTION
			This function will remove the special character from a string.
			I'm using Unicode Regular Expressions with the following categories
			\p{L} : any kind of letter from any language.
			\p{Nd} : a digit zero through nine in any script except ideographic
			
			http://www.regular-expressions.info/unicode.html
			http://unicode.org/reports/tr18/
		
		.PARAMETER String
			Specifies the String on which the special character will be removed
			
			.SpecialCharacterToKeep
			Specifies the special character to keep in the output
		
		.PARAMETER SpecialCharacterToKeep
			A description of the SpecialCharacterToKeep parameter.
		
		.EXAMPLE
			PS C:\> Remove-StringSpecialCharacter -String "^&*@wow*(&(*&@"
			wow
		
		.EXAMPLE
			PS C:\> Remove-StringSpecialCharacter -String "wow#@!`~)(\|?/}{-_=+*"
			
			wow
		
		.EXAMPLE
			PS C:\> Remove-StringSpecialCharacter -String "wow#@!`~)(\|?/}{-_=+*" -SpecialCharacterToKeep "*","_","-"
			wow-_*
		
		.NOTES
			Francois-Xavier Cat
			@lazywinadmin
			www.lazywinadmin.com
			github.com/lazywinadmin
	#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
			     ValueFromPipeline = $true,
			     Position = 0)][ValidateNotNullOrEmpty()][System.String[]]$String,
		[Parameter(Position = 1)][String[]]$SpecialCharacterToKeep
	)
	
	PROCESS {
		if ($PSBoundParameters["SpecialCharacterToKeep"]) {
			$SpecialCharacterToKeepArray = $SpecialCharacterToKeep.ToCharArray()
			$Regex = "[^\p{L}\p{Nd}"
			foreach ($Character in $SpecialCharacterToKeepArray) {
				Write-Verbose "Found $($Character)"
				IF ($Character -ceq "-") {
					
					$Regex += "\-"
				}
				else {
					$Regex += [Regex]::Escape($Character)
				}
				#$Regex += "/$character"
			}
			
			$Regex += "]+"
		}
		else {
			$Regex = "[^\p{L}\p{Nd}]+"
		}
		foreach ($Str in $string) {
			Write-Verbose -Message "RegEx is: $($Regex)"
			Write-Verbose -Message "Original String was: $Str"
			$Str -replace $regex, ""
		}
	}
}
function Test-Diacritics {
<#
	.SYNOPSIS
		Checks a Sting if it has Diacritics
	.DESCRIPTION
		Checks a Sting if it has Diacritics. And Returns true if the String has Diacritics
	.PARAMETER String
		A description of the String parameter.
	.PARAMETER IncludeBlanks
		A description of the IncludeBlanks parameter.
	.PARAMETER SpecialCharacterToKeep
		A description of the SpecialCharacterToKeep parameter.
	.EXAMPLE
		Test-Diacritics -string "äkdaolekr" -includeBlanks 
#>
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, Position = 0)][String]$String,
		[Parameter(Mandatory = $false, Position = 1)][switch]$IncludeBlanks = $true,
		[Parameter(Position = 2)][String[]]$SpecialCharacterToKeep
	)
	
	$RemovedDiacriticsString = Remove-Diacritics -text $String -RemoveBlanks:$IncludeBlanks
	$RemovedSpecialsString = Remove-SpecialCharacters -String $RemovedDiacriticsString -SpecialCharacterToKeep $SpecialCharacterToKeep
	
	if (($RemovedDiacriticsString -ceq $String) -and ($RemovedSpecialsString -ceq $String)) {
		return $false
	}
	else {
		Return $true
	}
}
#endregion Diacritics

#region Common WebRequest
Function get-webtable {
	<# 
    .SYNOPSIS 
    	Receives the specivied table from an HTML website
    .DESCRIPTION
    	Receives the specivied table from an HTML website
    .EXAMPLE 
    	get-webtable -Url www.google.de -TableNumber 0
    .PARAMETER Url
    	URL of the website
    .PARAMETER TableNumber
    	Defines the number of the Table
   	.OUTPUTS
    	HTML Table without HTML Tags
#>	
	Param (
		[Parameter(Mandatory = $true, Position = 0)][String]$Url,
		[Parameter(Mandatory = $False, Position = 1)][int]$TableNumber = 0
	)
	import-module loggingtoolbox
	# Use TLS1.2 to check the webrequest
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$invoke = Invoke-WebRequest  $url
	## Extract the tables out of the web request
	$tables = @($invoke.ParsedHtml.getElementsByTagName("TABLE"))
	$table = $tables[$TableNumber]
	$titles = @()
	$rows = @($table.Rows)
	
	## Go through all of the rows in the table
	ForEach ($row In $rows) {
		$cells = @($row.Cells)
		## If we've found a table header, remember its titles
		If ($cells[0].tagName -eq "TH") {
			$titles = @($cells | foreach-object {
					("" + $psitem.InnerText).Trim()
				})
			Continue
		}
		## If we haven't found any table headers, make up names "P1", "P2", etc.
		If (-not $titles) {
			$titles = @(1 .. ($cells.Count + 2) | foreach-object {
					"P$psitem"
				})
		}
		## Now go through the cells in the the row. For each, try to find the
		## title that represents that column and create a hashtable mapping those
		## titles to content
		$resultObject = [Ordered] @{
		}
		For ($counter = 0; $counter -lt $cells.Count; $counter++) {
			$title = $titles[$counter]
			If (-not $title) {
				Continue
			}
			$resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
		}
		## And finally cast that hashtable to a PSCustomObject
		[PSCustomObject]$resultObject
	}
}
#endregion Common WebRequest

#region Common Licensing
Function get-M365LicensesFriendlyNames {
	<# 
    .SYNOPSIS 
    	Imports License friendly list from Microsofts Website
    .DESCRIPTION
    	Imports License friendly list from Microsofts Website
    .EXAMPLE 
    	get-M365LicensesFriendlyNames
   	.OUTPUTS
    	Variable: $FriendlyLicenseList
#>	
	Param (
	)
	import-module loggingtoolbox
	$global:FriendlyLicenseList = get-webtable -url "https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference" -TableNumber 0 | select-object          @{
		N			     = "ProductName"; e = {
			$psitem.'Product name'
		}
	}, @{
		n			  = "StringID"; e = {
			$psitem.'String ID'
		}
	}, GUID, @{
		n					   = "ServicePlansIncluded"; e = {
			$psitem.'Service plans included'
		}
	}, @{
		n								  = "ServicePlansIncludedFriendlyName"; e = {
			$psitem.'Service plans included (friendly names)'
		}
	} | sort-object productname
	#return $global:FriendlyLicenseList
}
Function new-LicenseReport {
	<# 
    .SYNOPSIS 
        Create a M365 license report of the tenant
    .DESCRIPTION
        Create a M365 license report of the tenant
    .EXAMPLE 
        new-LicenseReport
    .EXAMPLE 
        new-LicenseReport -ExportHTML
    .EXAMPLE 
        new-LicenseReport -ExportHTML -ExportHTMLFilename c:\temp\test.html        
    .EXAMPLE 
        new-LicenseReport -ExportCSV
    .EXAMPLE 
        new-LicenseReport -ExportCSV -ExportCSVFilename c:\temp\test.csv       
    .PARAMETER ExportHTML
        Exports the Report to a filtered HTML File
    .PARAMETER ExportHTML   
        Fullname of the exported HTML file. Default if not set is : %userprofile%\LicenseReport_Date.html
    .PARAMETER Exportcsv
        Exports the Report to a filtered csv File
    .PARAMETER Exportcsv   
        Fullname of the exported csv file. Default if not set is : %userprofile%\LicenseReport_Date.csv
    .OUTPUTS
        Variable: $HTMLReport 
#>	
	Param (
		[Parameter(Mandatory = $false)][Switch]$ExportHTML,
		[Parameter(Mandatory = $false)][String]$ExportHTMLFilename = "$($env:LogPath)\CommonToolbox\new-LicenseReport\LicenseReport_$(get-date -format yyyy-MM-dd).html",
		[Parameter(Mandatory = $false)][Switch]$ExportCSV,
		[Parameter(Mandatory = $false)][String]$ExportCSVFilename = "$($env:LogPath)\CommonToolbox\new-LicenseReport\LicenseReport_$(get-date -format yyyy-MM-dd).csv",
		[Parameter(Mandatory = $false)][Switch]$Full,
		[Parameter(Mandatory = $false)][Switch]$Legend
		
	)
	import-module loggingtoolbox
	#connect-msolservice
	$header = @"
    <meta charset="UTF-8">
<style type="text/css">
	@font-face {
  		font-family: Verdana;
		}
	* {
		margin: 0px; 
		padding: 0px; 
		box-sizing: border-box;
	}
	body, html {
	height: 100%;
		display: inline-block;
		width: 100%;
		min-height: 100vh;
		align-items: center;
		padding: 33px 30px;
	}
	h1 {
		color: #333
		size: 20PX;
		align: center;
		border:none;
	}
	table {
		border-collapse: collapse;
		background: white;
		width: 100%;
		margin: 0 auto;
		position: relative;
		border: 1px solid #333; 
	}
	table td, table th {
		padding-left: 8px;  
		border: 1px solid #333;
	}
	table th {
		height: 30px;
		background: #333;
		color: white;
	}
	table thead tr {
		height: 30px;
		background: #36304a;
	}
	table tbody tr {
		height: 30px;
	}
	table tbody tr:last-child {
		border: 0;
	}
	table td, table th {
		text-align: left;
	}
	table td.l, table th.l {
		text-align: right;
	}
	table td.c, table th.c {
		text-align: center;
	}
	table td.r, table th.r {
		text-align: center;
	}
	table td.green {
		background-color: #71CC51;
		color: black;
	}
	table td.yellow {
		background-color: #FBE337;
		color: black;
	}
	table td.orange {
		background-color: #FF6C2F;
		color: white;
	}
	table td.red {
		background-color: #DC443A;
		color: white;
	}
	table td.grey {
		background-color: #5D5A59;
		color: white;
	}
	table td.violet {
		background-color: #5F4B8B;
		color: white;
	}
	table td.orchid {
		background-color: #AD5E99;
		color: white;
	}
	tbody tr:nth-child(even) {
		background-color: #f5f5f5;
	}
	tbody tr {
		font-size: 15px;
		color: #808080;
		line-height: 1.2;
		font-weight: unset;
	}
	b{border:none;}
</style>
"@
	
	get-M365LicensesFriendlyNames
	$Global:LicenseReport = @()
	$Global:LicenseReportFiltered = @()
	$Licenses = Get-MsolAccountSku | select-object SkuPartnumber, @{
		label						        = "UnassignedUnits"; expression = {
			$psitem.ActiveUnits - $psitem.ConsumedUnits
		}
	}, ActiveUnits | where-object {
		$psitem.ActiveUnits -ge 1
	}
	$LicenseFilter = "STANDARDPACK", "ENTERPRISEPACK", "MCOMEETADV", "MCOPSTN1", "MCOPSTN2", "MCOEV", "POWER_BI_PRO", "EMS", "VISIOCLIENT", "PROJECTPROFESSIONAL", "ATP_ENTERPRISE", "SPE_E3", "IDENTITY_THREAT_PROTECTION", "DYN365_ENTERPRISE_PLAN1", "PROJECTESSENTIALS", "DYN365_TEAM_MEMBERS", "SPE_E3_RPA1"
	$LicenseWarning = 25
	$licenseError = "0.1"
	ForEach ($License In $licenses) {
		If ($License.UnassignedUnits -le $LicenseWarning) {
			If (($License.ActiveUnits -eq 0) -or (($License.UnassignedUnits/$License.ActiveUnits) -le $licenseError)) {
				$label = "red$($license.UnassignedUnits)"
				$LicenseAlert = $true
			}
			Else {
				$label = "orange$($license.UnassignedUnits)"
				$LicenseAlert = $true
			}
		}
		Else {
			$label = "green$($license.UnassignedUnits)"
			$LicenseAlert = $false
		}
		If ($full) {
			$friendlyLicenseName = ($FriendlyLicenseList | where-object {
					$psitem.stringid -eq $license.skupartnumber
				}).ProductName
			If ($null -eq $friendlyLicenseName) {
				$friendlyLicenseName = $license.SKUPartNumber
			}
			If ($friendlyLicenseName -is [array]) {
				$friendlyLicenseName = $friendlyLicenseName[0]
			}
			$obj = $null = New-Object psobject -Property @{
				LicenseName     = $friendlyLicenseName
				UnassignedUnits = $label
				PurchasedUnits  = $license.ActiveUnits
				ConsumedUnits   = $license.ActiveUnits - $license.UnassignedUnits
			}
			$Global:LicenseReportFiltered += $obj
			$Global:LicenseReport += $obj
			$obj = $null
		}
		Else {
			If ($licensealert -eq $true) {
				$friendlyLicenseName = ($FriendlyLicenseList | where-object {
						$psitem.stringid -eq $license.skupartnumber
					}).ProductName
				If ($null -eq $friendlyLicenseName) {
					$friendlyLicenseName = $license.SKUPartNumber
				}
				If ($friendlyLicenseName -is [array]) {
					$friendlyLicenseName = $friendlyLicenseName[0]
				}
				
				$obj = $null = New-Object psobject -Property @{
					LicenseName     = $friendlyLicenseName
					UnassignedUnits = $label
					PurchasedUnits  = $license.ActiveUnits
					ConsumedUnits   = $license.ActiveUnits - $license.UnassignedUnits
				}
				If ($LicenseFilter -contains $license.skupartnumber) {
					$Global:LicenseReportFiltered += $obj
				}
				$Global:LicenseReport += $obj
				$obj = $null
			}
		}
	}
	
	#create HTML Body for mail
	$headline = $null
	$pre = $null
	$post = $null
	$htmlmail = $null
	$headline = "Microsoft 365 License Report from $(get-date -format dd-MM-yyyy)"
	$pre = '<h1>' + $headline + '</h1>'
	$post = @()
	$post += '</br>'
	If ($Legend) {
		$post += '<table><tr><td class="green">Green</td><td>Enough licenses available</td>'
		$post += '<tr><td class="orange">Orange</td><td>Less than ' + $($licensewarning) + '</td>'
		$post += '<tr><td class="red">Red</td><td>Overassigned, no liceneses left or less than ' + $licenseError + '</td></table>'
	}
	
	$htmlmail = $Global:LicenseReportFiltered | select-object LicenseName, UnassignedUnits, PurchasedUnits, ConsumedUnits | sort-object licensename | convertto-html -head $header -PreContent $pre -PostContent $post | Out-String
	$Global:HTMLReport = $htmlmail.replace('<td>red', '<td class="red">').replace('<td>green', '<td class="green">').replace('<td>orange', '<td class="orange">').replace('<td>yellow', '<td class="yellow">').replace('<td>violet', '<td class="violet">').replace('<td>orchid', '<td class="orchid">').replace('<td>grey', '<td class="grey">')
	
	If ($ExportHTML) {
		$Global:HTMLReport | out-file $ExportHTMLFilename
	}
	If ($ExportCSV) {
		$Global:LicenseReport | select-object LicenseName, @{
			n																												    = "UnassignedUnits"; e = {
				$psitem.UnassignedUnits.replace('red', '').replace('green', '').replace('orange', '').replace('yellow', '').replace('violet', '').replace('orchid', '').replace('grey', '')
			}
		}, PurchasedUnits, ConsumedUnits | sort-object licensename | export-csv $ExportCSVFilename -delimiter ";" -NoTypeInformation -Encoding utf8
	}
	
}
#endregion Common Licensing

#region Translation
function Get-TextTranslation {
	<#
	.SYNOPSIS
		Converts text in different language with deepL
	.DESCRIPTION
		Converts text in different language with deepL
	.PARAMETER text
		A description of the text parameter.
	.PARAMETER SourceLanguage
		A description of the SourceLanguage parameter.
	.PARAMETER TargetLanguage
		A description of the TargetLanguage parameter.
	.EXAMPLE
		Get-TextTranslation -text 'Value1' -SourceLanguage 'Value2' -TargetLanguage 'Value3'
	#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true, Position = 0)][string]$text,
		[Parameter(Mandatory = $true, Position = 1)][ValidateSet('FR', 'EN', 'DE', 'IT', 'ES')][string]$SourceLanguage = 'EN',
		[Parameter(Mandatory = $true, Position = 2)][ValidateSet('FR', 'EN', 'DE', 'IT', 'ES')][string]$TargetLanguage = 'DE'
	)
	
	Add-Type -AssemblyName System.Web
	$URL = "https://api-free.deepl.com/v2/translate"
	$Header = @{
		"Authorization" = "DeepL-Auth-Key 5634a8d5-a2f5-404d-9239-efaad75a6324:fx"
	}
	$Body = $null = @{
		text	      = $text
		target_lang = $TargetLanguage
		source_lang = $SourceLanguage
	}
	$global:TranslatedText = (Invoke-RestMethod -Uri "https://api-free.deepl.com/v2/translate" -Method Post -Body $Body -Headers $Header).translations.text
	$global:TranslatedText
	
}
#endregion Translation

#region Installation
function Install-LatestPowerShell7Version {
<#
	.SYNOPSIS
		This function will install the latest PS7 Version
	.DESCRIPTION
		This function will install the latest PS7 Version
	.PARAMETER winget
		A description of the winget parameter.
	.EXAMPLE
		Install-LatestPowerShell7Version
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false,Position = 0)][switch]$winget = $true
	)
	
	If (!([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))) {
		Write-Host "PowerShell is not running as an Administrator. Please run PowerShell with Administrator permission" -ForegroundColor white -BackgroundColor red
	}
	Else {
		if($winget){Invoke-Expression "winget install --id microsoft.powershell --source winget"}
		else{Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI"}
	}
	
}
Function Update-PowerShellEnviroment {
	<#
	.SYNOPSIS
		Updates Powershell 7 and all installed modules
	.DESCRIPTION
		Updates Powershell 7 and all installed modules
	.PARAMETER mailaddress
		This parameter defines the UPN of the account with access to the AzureDevOps repository
	.PARAMETER repoPATPath
		The URL to the AzureDevOps repository
	.EXAMPLE
		Update-PowerShellEnviroment
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Position = 0)][String]$mailaddress = "",
		[Parameter(Position = 0)][String]$repoPATPath = ""
	)
	$WriteLogCSVCommonParamsHash, $WriteLogCSVErrorParamsHash, $WriteLogCSVErrorsHash, $WriteLogCSVNoticeParamsHash, $WriteLogCSVWarningParamsHash = Get-DefaultLoggingParameters -FunctionNameStr ($MyInvocation.MyCommand).name -Module "CommonToolbox" #($PSCommandPath).split("\")[-1].split(".")[0]
	$WriteLogCSVErrorParamsHash.consoleoutput = $true
	$WriteLogCSVWarningParamsHash.consoleoutput = $true
	$WriteLogCSVCommonParamsHash.add("ObjectName", "")
	$outdatedModules = @()
	$env:ModulesTOManuallyRemove = $null = @()
	$uri = "https://pkgs.dev.azure.com/ArvatoSystemsGmbH/MessColab/_packaging/MessColabPSModules/nuget/v2"
	$shortURI = "pkgs.dev.azure.com/ArvatoSystemsGmbH/MessColab/"
	if (($PSVersionTable.PSVersion.ToString() -notlike '7.*') -and (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		Install-LatestPowerShell7Version
		
	}
	if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		$ModulesNotFiltered = $null = Get-Module -ListAvailable
		$ModuleGroups = $null = $ModulesNotFiltered | group-Object -Property Name
		foreach ($ModuleGroup in $ModuleGroups) {
			$ModuleVersionCount = $ModuleGroup.count
			$module = ($ModuleGroup.group | Sort-Object -Property version -Descending)[0]
			$WriteLogCSVCommonParamsHash.Objectname = "$($Module.name)"
			if ($module.RepositorySourceLocation -match "//www.powershellgallery.com/") {
				try {
					$GalleryModule = Find-Module $module.name -Repository PSGallery
					Write-Debug "Updating Module $($Module.Name)"
					Update-Module $Module.name -Force -ErrorAction Stop -confirm:$false
					write-LogCSV -text "Module $($module.Name) was Updated" @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
					Import-Module $GalleryModule.name -RequiredVersion $GalleryModule.Version -Force -Global
					write-LogCSV -text "Module $($module.Name) was Imported" @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
					$ImportedModules = Get-Module $module.name
					foreach ($ImportedModule in $ImportedModules) {
						if ($ImportedModule.Version -ne $GalleryModule.Version) {
							Remove-Module $ImportedModule -force
							write-LogCSV -text "Module $($ImportedModule) - $($ImportedModule.Version) was Removed out of Instance" @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
						}
					}
					if ($ModuleVersionCount -gt 1) {
						$outdatedModules += ($ModuleGroups[0].group | Sort-Object -Property version)[0 .. ($ModuleVersionCount - 2)]
					}
				}
				catch {
					write-LogCSV -text "Module $($module.Name) Failed to update" @WriteLogCSVCommonParamsHash @WriteLogCSVErrorParamsHash
					write-LogCSV -text "`"$($error.exception)`"" @WriteLogCSVCommonParamsHash @WriteLogCSVErrorsHash
				}
			}
			elseif ($module.RepositorySourceLocation -match $shortURI) {
				try {
					if ([String]::IsNullOrEmpty($mailaddress)) {
						$mailaddress = Read-Host -Prompt "Your Mailadress to authenticate to the MessCollab Repository"
					}
					if ([String]::IsNullOrEmpty($repoPATPath)) {
						$repoPATPath = Read-Host -Prompt "The path to your PAT clixml of the repo leave empty for it to be: $($Env:USERPROFILE)\PSrepoPat.xml"
						if ([String]::IsNullOrEmpty($repoPATPath)) {
							$repoPATPath = "$($Env:USERPROFILE)\PSrepoPat.xml"
						}
					}
					$credsAzureDevopsServices = New-Object System.Management.Automation.PSCredential($mailaddress, (Import-Clixml $repoPATPath))
					$Customrepository = Get-Psrepository | where-object {
						$psitem.sourceLocation -eq $uri
					}
					$GalleryModule = Find-Module $module.name -Repository $Customrepository.name -Credential $credsAzureDevopsServices
					Update-Module -Name $module.name -Credential $credsAzureDevopsServices -Force -ErrorAction Stop -confirm:$false
					write-LogCSV -text "Module $($module.Name) was Installed" @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
					Import-Module $GalleryModule.name -RequiredVersion $GalleryModule.Version -Force -Global
					write-LogCSV -text "Module $($module.Name) was Imported" @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
					$ImportedModules = Get-Module $module.name
					foreach ($ImportedModule in $ImportedModules) {
						if ($ImportedModule.Version -ne $GalleryModule.Version) {
							Remove-Module $ImportedModule
							write-LogCSV -text "Module $($ImportedModule) - $($ImportedModule.Version) was Removed out of Instance" @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
						}
					}
					if ($ModuleVersionCount -gt 1) {
						$outdatedModules += ($ModuleGroups[0].group | Sort-Object -Property version)[0 .. ($ModuleVersionCount - 2)]
					}
				}
				catch {
					write-LogCSV -text "Module $($module.Name) failed to update." @WriteLogCSVCommonParamsHash @WriteLogCSVErrorParamsHash
					write-LogCSV -text "`"$($error.exception)`"" @WriteLogCSVCommonParamsHash @WriteLogCSVErrorsHash
				}
			}
			else {
				write-LogCSV -text "Module $($module.Name) not installed from recognised repository" @WriteLogCSVCommonParamsHash @WriteLogCSVErrorParamsHash
			}
		}
		foreach ($outdatedModule in $outdatedModules) {
			try {
				$outdatedModule | Remove-Module -Force
				write-LogCSV -text "Module $($outdatedModule.Name) uninstalled." @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
			}
			catch {
				write-LogCSV -text "Module $($outdatedModule.Name) failed to uninstall." @WriteLogCSVCommonParamsHash @WriteLogCSVErrorParamsHash
				write-LogCSV -text "`"$($error.exception)`"" @WriteLogCSVCommonParamsHash @WriteLogCSVErrorsHash
				$env:ModulesTOManuallyRemove += $outdatedModule
			}
			$WriteLogCSVCommonParamsHash.Objectname = "$($outdatedModule.name)"
			try {
				$outdatedModule | Uninstall-Module -force -ErrorAction Stop
				write-LogCSV -text "Module $($outdatedModule.Name) uninstalled." @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
			}
			catch {
				try {
					Remove-Item -Path $outdatedModule.ModuleBase -Recurse -Force -ErrorAction Stop
					write-LogCSV -text "Module $($outdatedModule.Name) uninstalled." @WriteLogCSVCommonParamsHash @WriteLogCSVNoticeParamsHash
				}
				catch {
					write-LogCSV -text "Module $($outdatedModule.Name) failed to uninstall." @WriteLogCSVCommonParamsHash @WriteLogCSVErrorParamsHash
					write-LogCSV -text "`"$($error.exception)`"" @WriteLogCSVCommonParamsHash @WriteLogCSVErrorsHash
					$env:ModulesTOManuallyRemove += $outdatedModule
				}
			}
		}
	}
}
#endregion Installation