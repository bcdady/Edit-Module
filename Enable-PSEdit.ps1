#!/usr/local/bin/pwsh
#Requires -Version 3
[CmdletBinding()]
Param()
#Set-StrictMode -Version latest

# Uncomment the following 2 lines for testing profile scripts with Verbose output
#'$VerbosePreference = ''Continue'''
#$VerbosePreference = 'Continue'

Write-Verbose -Message 'Detect -Verbose $VerbosePreference'
switch ($VerbosePreference) {
  Stop             { $IsVerbose = $True }
  Inquire          { $IsVerbose = $True }
  Continue         { $IsVerbose = $True }
  SilentlyContinue { $IsVerbose = $False }
  Default          { if ('Verbose' -in $PSBoundParameters.Keys) {$IsVerbose = $True} else {$IsVerbose = $False} }
}
Write-Verbose -Message ('$VerbosePreference = ''{0}'' : $IsVerbose = ''{1}''' -f $VerbosePreference, $IsVerbose)

#Region MyScriptInfo
    Write-Verbose -Message '[Open-PSEdit] Populating $MyScriptInfo'
    $Private:MyCommandName        = $MyInvocation.MyCommand.Name
    $Private:MyCommandPath        = $MyInvocation.MyCommand.Path
    $Private:MyCommandType        = $MyInvocation.MyCommand.CommandType
    $Private:MyCommandModule      = $MyInvocation.MyCommand.Module
    $Private:MyModuleName         = $MyInvocation.MyCommand.ModuleName
    $Private:MyCommandParameters  = $MyInvocation.MyCommand.Parameters
    $Private:MyParameterSets      = $MyInvocation.MyCommand.ParameterSets
    $Private:MyRemotingCapability = $MyInvocation.MyCommand.RemotingCapability
    $Private:MyVisibility         = $MyInvocation.MyCommand.Visibility

    if (($null -eq $Private:MyCommandName) -or ($null -eq $Private:MyCommandPath)) {
        # We didn't get a successful command / script name or path from $MyInvocation, so check with CallStack
        Write-Verbose -Message 'Getting PSCallStack [$CallStack = Get-PSCallStack]'
        $Private:CallStack      = Get-PSCallStack | Select-Object -First 1
        $Private:myScriptName   = $Private:CallStack.ScriptName
        $Private:myCommand      = $Private:CallStack.Command
        Write-Verbose -Message ('$ScriptName: {0}' -f $Private:MyScriptName)
        Write-Verbose -Message ('$Command: {0}' -f $Private:MyCommand)
        Write-Verbose -Message 'Assigning previously null MyCommand variables with CallStack values'
        $Private:MyCommandPath    = $Private:MyScriptName
        $Private:MyCommandName    = $Private:MyCommand
    }
    #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
    $Private:properties = [ordered]@{
        'CommandName'        = $Private:MyCommandName
        'CommandPath'        = $Private:MyCommandPath
        'CommandType'        = $Private:MyCommandType
        'CommandModule'      = $Private:MyCommandModule
        'ModuleName'         = $Private:MyModuleName
        'CommandParameters'  = $Private:MyCommandParameters.Keys
        'ParameterSets'      = $Private:MyParameterSets
        'RemotingCapability' = $Private:MyRemotingCapability
        'Visibility'         = $Private:MyVisibility
    }
    $Private:MyScriptInfo = New-Object -TypeName PSObject -Property $Private:properties
    Write-Verbose -Message '[Open-PSEdit] $MyScriptInfo populated'

    if ('Verbose' -in $PSBoundParameters.Keys) {
        Write-Verbose -Message 'Output Level is [Verbose]. $MyScriptInfo is:'
        $Private:MyScriptInfo
    }
#End Region

# Detect older versions of PowerShell and add in new automatic variables for more cross-platform consistency in PS Core
if (-not ((Get-Variable -Name IsWindows -ErrorAction Ignore) -eq $true)) { 
    Set-Variable -Name IsWindows -Value $false -ErrorAction Ignore
    if ($Host.Version.Major -le 5) {
        Set-Variable -Name IsWindows -Value $true -ErrorAction Ignore
    }
}

if ($IsWindows) {
    $hostOS = 'Windows'
    $hostOSCaption = $((Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption).Caption) -replace 'Microsoft ', ''
    # Check admin rights / role; same approach as Test-LocalAdmin function in Sperry module
    $IsAdmin = (([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
}

Write-Verbose -Message 'Declaring Function Compare-PSEdit'
Function Compare-PSEdit {
    <#
        .SYNOPSIS
            Compare-PSEdit evaluates the version of $Env:PSEdit against the latest version available from the shared corporate repo
        .DESCRIPTION
            Compare-PSEdit returns the path value of the currently configured $Env:PSEdit variable.
            The $Env:PSEdit variable points to the path of the currently configured PowerShell editor, such as ISE or VScode.
        .EXAMPLE
            .> Compare-PSEdit

            C:\Program Files\Microsoft VS Code\bin\code.cmd
    #>
    Param (
        [Parameter(Position=0)]
        [ValidateScript({Test-Path -Path (Resolve-Path -Path $PSItem)})]
        [String]
        $Path = 'R:\IT\Microsoft Tools\VSCode\vscode\app\Code.exe'
    )

    if (Get-PSEdit) {
        Write-Verbose -Message 'Getting version of file for environment variable PSEdit'
        $PSEditVer =((Get-Item -Path $Env:PSEdit | Select-Object -Property VersionInfo).VersionInfo).ProductVersion
        if (-not $PSEditVer) {
            $PSEditVer = ((Get-Item -Path ($Env:PSEdit -replace '\\bin\\code\.cmd','\code.exe') | Select-Object -Property VersionInfo).VersionInfo).ProductVersion
            #Write-Warning -Message ("Unable to determine Product Version of `$Env:PSEdit: ({0}).`n`n Check that `$Env:PSEdit points to a .exe file. Update using`n Assert-PSEdit [-Path H:\vscode\app\Code.exe] `nif necesarry.`n`n" -f (Get-Item -Path $Env:PSEdit | Select-Object -Property FullName).FullName)
            #throw 'Unable to determine VS Code Product Version'
        }
        Write-Verbose -Message ('Getting Version of {0}' -f $Path)
        $VSCodeVer =((Get-Item -Path $Path | Select-Object -Property VersionInfo).VersionInfo).ProductVersion

        if ($PSEditVer -eq $VSCodeVer) {
            Write-Output -InputObject 'PSEdit is current.'
        } else {
            Write-Warning -Message ('  Your copy of VS Code is older ({0}). Run Update-VSCode to update to {1}.' -f $PSEditVer, $VSCodeVer)
        }
    } else {
        Write-Output -InputObject "Env:PSEdit is Undefined.`nRun Assert-PSEdit to declare or detect Path to available editor."
    }
}

Write-Verbose -Message 'Declaring Function Update-VSCode'
Function Update-VSCode {
    <#
        .SYNOPSIS
            Update-VSCode updates the user's own copy of VS Code from the shared corporate repo.
        .DESCRIPTION
            Update-VSCode locates and calls the existing R:\IT\Microsoft Tools\VSCode\#Setup_my_VSCode.ps1
        .EXAMPLE
            .> Update-VSCode

            If found already running, you'll see this warning:xa

                WARNING: Found editor process is active:
                .\vscode\app\code.exe
                Please close before proceeding.
                Press Enter to continue...:
    #>
    Param (
        [Parameter(Position=0)]
        [ValidateScript({Test-Path -Path (Resolve-Path -Path $PSItem)})]
        [Alias('PortableSetupPath','SetupPath')]
        [String]
        $ScriptPath = 'R:\IT\Microsoft Tools\VSCode\#Setup_my_VSCode.ps1'
    )

    if (Get-Process -Name code -ErrorAction Ignore) {
        Write-Warning -Message ("Found editor process is active:`n`t`t{0}`n`tPlease close before proceeding." -f (Get-Process -Name code | Select-Object -Property Path -Unique).Path)
        pause
    }
    Write-Verbose -Message ('Running VSCode Setup: {0}' -f $Path)
    & $Path
}

Write-Verbose -Message 'Declaring Function Install-VSCode'
function Install-VSCode {
    [cmdletbinding()]
    Param(
      [Parameter(Position = 0)]
      [ValidateScript({Test-Path -Path $_})]
      [Alias('Source','Path')]
      [string]
      $SourcePath = 'R:\it\Microsoft Tools\VSCode'
      ,
      [Parameter(Position = 1)]
      [ValidateScript({Test-Path -Path $_})]
      [Alias('INSTALLDIR','Target','Destination')]
      [string]
      $InstallPath = (Join-Path -Path $HOME -ChildPath 'Programs\VSCode')
    )
  
    if ((Get-Item -Path $SourcePath).PSIsContainer) {
      $private:VSCodeUserSetup = Join-Path -Path $SourcePath -ChildPath 'VSCodeUserSetup-*.exe' -Resolve | Select-Object -Last 1
    } else {
      $private:VSCodeUserSetup = $SourcePath
    }
    Write-Verbose -Message ('VSCodeUserSetup is {0}' -f $private:VSCodeUserSetup)
  
    if (-not (Get-Item -Path $InstallPath).PSIsContainer) {
      Write-Verbose -Message '$InstallPath is Container'
      $InstallPath = Split-Path -Path $InstallPath -Parent
    }
    Write-Verbose -Message ('$InstallPath is {0}' -f $InstallPath)
    
    if ($null -ne ($code = Get-Process -Name code -ErrorAction SilentlyContinue) ) {
      Write-Warning -Message ('{0} is running ({1}). Please close before proceeding with it''s setup' -f ($code | Select-Object -Property Description -Unique).Description, ($code | Select-Object -Property Path -Unique).Path)
      Pause
    }
  
    $private:VSCodeArgsList  = ('/SP- /SILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /LANG=english /DIR="{0}" /TASKS=addcontextmenufiles,associatewithfiles' -f $InstallPath)
    Write-Verbose -Message ('Start-Process -FilePath {0} -ArgumentList {1} -Wait' -f $private:VSCodeUserSetup, $private:VSCodeArgsList)
    Start-Process -FilePath $private:VSCodeUserSetup -ArgumentList $private:VSCodeArgsList -Wait
  
    <#
        # Install VSCode via script?
        # First, check if PackageManagement is up to date to support  in GBCI citrix image - as of 11/27/2018
  
        if ((Get-Module -Name PackageManagement).Version -lt '1.1.7') {
        Install-Package -Name PackageManagement -Scope CurrentUser -Force -AllowClobber
        } else {
        (Get-Module -Name PackageManagement).Version
        }
          
        #Install-Script -Scope CurrentUser -Repository PSGallery -AcceptLicense -Name Install-VSCode -NoPathUpdate
        #Install-VSCode.ps1 -?
    #>
}

Write-Verbose -Message 'Declaring Function Set-VSCodeRegistryCommand'
Function Set-VSCodeRegistryCommand {
    [CmdletBinding()]
    Param (
        [Parameter(Position=0)]
        [string]
        $ProgID = '*',
        [Parameter(Position=1)]
        [ValidateScript({Test-Path -Path $PSItem -PathType Container})]
        [string]
        $Path = $Env:PSEdit,
        [Parameter(Position=2)]
        [ValidateSet('HKLM','HKCU')]
        [string]
        $PSDrive = 'HKCU',
        [Parameter(Position=3)]
        [ValidateSet('open','edit','VSCode')]
        [string]
        $Verb = 'open'
    )

    # -- if $ProgID is * (wildcard), then the Verb is 'VSCode' instead of the traditional 'open'
    if ($ProgID -eq '*') {
        # HKCU:\SOFTWARE\Classes\*\shell\VSCode\command
        $verb = 'VSCode'
    }

    if ($ProgID -match '^vscode(\..+)$') {
        # grab the file extension after vscode.
        $FileExt = $Matches[1]

        if (Test-Path -LiteralPath ('{0}:\SOFTWARE\Classes\{1}' -f $PSDrive, $FileExt)) {
            $OpenWithProgid = Get-ChildItem -LiteralPath ('{0}:\SOFTWARE\Classes\{1}' -f $PSDrive, $FileExt) | Select-Object -ExpandProperty Property
            Write-Verbose -Message ('File extension {0} is associated with ProgID {1}' -f $FileExt, $OpenWithProgid)
        } else {
            Write-Verbose -Message ('Associating New file extension {0} with ProgID {1}' -f $FileExt, $ProgID)
            $null = New-Item -Path ('{0}:\SOFTWARE\Classes\{1}\OpenWithProgids' -f $PSDrive, $FileExt) -Force
            $null = New-ItemProperty -LiteralPath ('{0}:\SOFTWARE\Classes\{1}\OpenWithProgids' -f $PSDrive, $FileExt) -Name $ProgID -Value $null
        }
    }

    if (Test-Path -LiteralPath ('{0}:\SOFTWARE\Classes\{1}\shell\{2}\command' -f $PSDrive, $ProgID, $Verb) -ErrorAction SilentlyContinue) {
        # Registry key exists 
        # (Over)Write the CURRENT_USER registry data value for Explorer right-click 'Open with Code'
        Write-Verbose -Message ('Get-Item -LiteralPath {0}:\SOFTWARE\Classes\{1}\shell\{2}\command' -f $PSDrive, $ProgID, $Verb)
        $ShellCommand = (Get-Item -LiteralPath ('{0}:\SOFTWARE\Classes\{1}\shell\{2}\command' -f $PSDrive, $ProgID, $Verb)).GetValue($null)
        Write-Verbose -Message ('Initial command is {0}' -f $ShellCommand)
        $NewCommand = $ShellCommand -replace '^(\".+?\")\s*?(.+)?(\"%1\")$', ('$1 --reuse-window --user-data-dir "{0}\data\user-data" --extensions-dir "{0}\data\extensions" $3' -f (Split-path -Path $Path))
        Write-Verbose -Message ('Updated command is {0}' -f  $NewCommand)

        Write-Verbose -Message ('Set-ItemProperty -LiteralPath {0}:\SOFTWARE\Classes\{1}\shell\{2}\command -Name ''(Default)'' -Value {3}' -f $PSDrive, $ProgID, $Verb, $NewCommand)
        Set-ItemProperty -LiteralPath ('{0}:\SOFTWARE\Classes\{1}\shell\{2}\command' -f $PSDrive, $ProgID, $Verb) -Name '(Default)' -Value $NewCommand
    } else {
        # Registry key does NOT exist
        $NewCommand = ('{0} --reuse-window --user-data-dir "{1}\data\user-data" --extensions-dir "{1}\data\extensions" "%1"' -f $Path, (Split-path -Path $Path))
        Write-Verbose -Message ('NEW-ItemProperty -LiteralPath {0}:\SOFTWARE\Classes\{1}\shell\{2}\command -Name ''(Default)'' -Value {3}' -f $PSDrive, $ProgID, $Verb, $NewCommand)
        New-Item -Path ('{0}:\SOFTWARE\Classes\{1}\shell\{2}\command' -f $PSDrive, $ProgID, $Verb) -Force
        New-ItemProperty -LiteralPath ('{0}:\SOFTWARE\Classes\{1}\shell\{2}\command' -f $PSDrive, $ProgID, $Verb) -Name '(Default)' -Value $NewCommand | Format-List -Property '(default)'
        if ($ProgID -eq '*') {
            # HKCU:\SOFTWARE\Classes\*\shell\VSCode\command
            Write-Verbose -Message ('New-ItemProperty -Path {0}:\SOFTWARE\Classes\{1}\shell\{2} -Name command, Icon -Value [various]' -f $PSDrive, $ProgID, $Verb)
            $null = New-Item -Path ('{0}:\SOFTWARE\Classes\{1}\shell\{2}' -f $PSDrive, $ProgID, $Verb) -Force
            New-ItemProperty -LiteralPath ('{0}:\SOFTWARE\Classes\{1}\shell\{2}' -f $PSDrive, $ProgID, $Verb) -Name '(Default)' -Value 'Open w&ith Code'
            $null = New-ItemProperty -LiteralPath ('{0}:\SOFTWARE\Classes\{1}\shell\{2}' -f $PSDrive, $ProgID, $Verb) -Name 'Icon' -Value $Env:PSEdit

            Write-Verbose -Message ('New-ItemProperty -Path {0}:\SOFTWARE\Applications\Code.exe -Name shell-open-command, DefaultIconIcon -Value [various]' -f $PSDrive)
            $null = New-Item -Path ('{0}:\SOFTWARE\Classes\Applications\Code.exe\shell\open\command' -f $PSDrive) -Force
            $null = New-ItemProperty -LiteralPath ('{0}:\SOFTWARE\Classes\Applications\Code.exe' -f $PSDrive) -Name 'DefaultIcon' -Value ('{0}\resources\app\resources\win32\default.ico' -f (Split-path -Path $Path)) -ErrorAction SilentlyContinue
            New-ItemProperty -LiteralPath ('{0}:\SOFTWARE\Classes\Applications\Code.exe\shell\open\command' -f $PSDrive) -Name '(Default)' -Value $NewCommand | Format-List -Property '(default)'
        }
    }

    # Cleanup
    Remove-Variable -Name ShellCommand -ErrorAction SilentlyContinue
    Remove-Variable -Name NewCommand   -ErrorAction SilentlyContinue
}

Write-Verbose -Message 'Declaring Function Update-VSCodeRegPath'
Function Update-VSCodeRegPath {
    [CmdletBinding()]
    Param (
        [Parameter(Position=0)]
        [string]
        $FileType = 'vscode*',
        [Parameter(Position=1)]
        [ValidateScript({Test-Path -Path $PSItem -PathType Container})]
        [string]
        $Path = $(Split-Path -LiteralPath $Env:PSEdit)
    )

    # Check if $FileType looks like a filename extention or a ProgID
    # - if it's an extension :: file type association, then first collect the list of associated ProgIDs
    # - - Test childpath $FileType \ OpenWithProgids, and if true:
    # $OpenWithProgids = (Get-Item -LiteralPath Registry::HKEY_CURRENT_USER\Software\Classes\.ps1\OpenWithProgids).GetValueNames()
    # Then for each $OpenWithProgid, pass it (back) through this function

    if ($FileType.StartsWith('.')) {
        # The string in $FileType starts with a period, so it looks like an extension key and not a ProgID key
        Write-Verbose -Message (' FileType parameter ({0}) looks like an extension; looking up it''s ProgID ...' -f  $FileType)
#        $ProgIDCollection = (Get-Item -LiteralPath ('Registry::HKEY_CURRENT_USER\Software\Classes\{0}\OpenWithProgids' -f $FileType)).GetValueNames()
#        $ProgIDCollection | ForEach-Object -Process {
#            Write-Verbose -Message (' > Update-VSCodeRegPath -FileType {0}' -f  $_)
            Update-VSCodeRegPath -FileType $((Get-Item -LiteralPath ('Registry::HKEY_CURRENT_USER\Software\Classes\{0}\OpenWithProgids' -f $FileType)).GetValueNames())
#        }
        Write-Verbose -Message ' # Done! [Break]'
        Break
    }

    # Check that $Path is valid
    # Test-Path -Path $Path -PathType Container -ErrorAction Stop

    # Get 'resources' path (within VSCode program directory) for updating any invalid registry values with
    Write-Verbose -Message ('$resourcesPath = Join-Path -Path {0} -ChildPath ''resources''' -f  $Path)
    $resourcesPath = Join-Path -Path $Path -ChildPath 'resources' -Resolve -ErrorAction Stop
    Write-Verbose -Message ('$resourcesPath = {0}' -f  $resourcesPath)

    Write-Verbose -Message ('Test-Path -Path ''HKCU:\SOFTWARE\Classes\{0}''' -f  $FileType)
    Test-Path -Path ('HKCU:\Software\Classes\{0}' -f $FileType) -ErrorAction Stop

    if ($FileType -match '^\..*$') {
        # The string in $FileType contains a wildcard, so we must use -Path, and not -LiteralPath (which can commonly be more reliable for Registry paths)
        Write-Verbose -Message ('Get-Item -Path ''HKCU:\SOFTWARE\Classes\{0}''' -f  $FileType)
        $FTACollection = Get-Item -Path ('HKCU:\Software\Classes\{0}' -f $FileType)
    } else {
        $FTACollection = Get-Item -LiteralPath ('HKCU:\Software\Classes\{0}' -f $FileType)
    }

    if ($null -ne (Select-Object -InputObject $FTACollection -Property Length -ErrorAction SilentlyContinue).Length ) {
        Write-Verbose -Message (' Get-Item collected {0} values into $FTACollection' -f $FTACollection.Length)
    } else {
        Write-Verbose -Message ' Get-Item collected 1 value into $FTACollection'
    }

    Write-Verbose -Message ' # entering foreach $FTACollection loop'
    $FTACollection | ForEach-Object -Process {
        
        if (-not (Test-Path -LiteralPath ('HKCU:\SOFTWARE\Classes\{0}\shell\open\command' -f $PSItem.PSChildName))) {
            Write-Verbose -Message 'No Shell ''Open'' Command for this ProgID; next'
            continue
        }
        $AppID = (Get-Item -LiteralPath ('HKCU:\SOFTWARE\Classes\{0}' -f $PSItem.PSChildName)).GetValue($null)
        Write-Verbose -Message ("ProgID {0} is associated as '{1}'" -f $PSItem.PSChildName, $AppID) -ErrorAction SilentlyContinue
        Write-Verbose -Message ('Get-Item -LiteralPath ''HKCU:\SOFTWARE\Classes\{0}\shell\open\command''' -f $PSItem.PSChildName)
        $PreviousErrorPreference = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        $ShellCommand = (Get-Item -LiteralPath ('HKCU:\SOFTWARE\Classes\{0}\shell\open\command' -f $PSItem.PSChildName)).GetValue($null)
        $ErrorActionPreference = $PreviousErrorPreference
        #if (-not $?) { Write-Warning -Message 'No Shell Command for this ProgID; Continue'; Continue}
        Write-Verbose -Message ('Initial command is {0}' -f $ShellCommand)

        # From: "H:\Programs\VSCode\Code.exe" "%1"
        # To:   "H:\Programs\VSCode\Code.exe" --reuse-window  --user-data-dir "H:\Programs\VSCode\data\user-data" --extensions-dir "H:\Programs\VSCode\data\extensions" "%1"
        $NewCommand = $ShellCommand -replace '^(\".+?\")\s*?(.+)?(\"%1\")$', ('$1 --reuse-window --user-data-dir "{0}\data\user-data" --extensions-dir "{0}\data\extensions" $3' -f $Path)
        Write-Verbose -Message ('Updated command is {0}' -f  $NewCommand)

        Set-ItemProperty -LiteralPath ('HKCU:\SOFTWARE\Classes\{0}\shell\open\command' -f $PSItem.PSChildName) -Name '(Default)' -Value $NewCommand

        Clear-Variable -Name ShellCommand
        Clear-Variable -Name NewCommand

        if (Test-Path -LiteralPath ('HKCU:\SOFTWARE\Classes\{0}\DefaultIcon' -f $PSItem.PSChildName)) {
            $IconPath = (Get-Item -LiteralPath ('HKCU:\SOFTWARE\Classes\{0}\DefaultIcon' -f $PSItem.PSChildName)).GetValue($null)
            Write-Verbose -Message ('Initial DefaultIcon is {0}' -f  $IconPath)
            if (Test-Path -LiteralPath $IconPath) {
                Write-Verbose -Message '$IconPath appears valid: {0}'
            } else {
                # Presume initial $IconPath is invalid, so update and check again
                $IconPath = $IconPath -replace '.+\\resources\\(\S+$)', ('{0}\$1' -f $resourcesPath)
                Write-Verbose -Message ('Updated DefaultIcon is {0}' -f  $IconPath)
                Write-Verbose -Message ('Is updated $IconPath valid?: {0}' -f (Test-Path -LiteralPath $IconPath))
                if (Test-Path -LiteralPath $IconPath) {
                    Write-Verbose -Message ('Set-ItemProperty -Path ''HKCU:\SOFTWARE\Classes\{0}\DefaultIcon'' -Name ''(Default)'' -Value {1}' -f $PSItem.PSChildName, $IconPath)
                    Set-ItemProperty -Path ('HKCU:\SOFTWARE\Classes\{0}\DefaultIcon' -f $PSItem.PSChildName) -Name '(Default)' -Value $IconPath
                } else {
                    Write-Verbose -Message 'Warning!: DefaultIcon points to an invalid path; will not update in registry'
                }
            }
        } else {
            Write-Verbose -Message 'No DefaultIcon defined in registry for this ProgID.'
        }
        if ($IsVerbose) {pause}
    }
    Remove-Variable -Name PreviousErrorPreference
    Write-Verbose -Message ' # exiting foreach $FTACollection loop'
}

Write-Verbose -Message 'Declaring Function Remove-VSCUserRegistry'
Function Remove-VSCUserRegistry {
    [CmdletBinding()]
    param()

    $PreviousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    Get-ChildItem -Path 'HKCU:\Software\Classes\.*' | Where-Object -FilterScript {(Get-ChildItem -Path $_.PSPath).Property -match '^VSCode'} | Remove-Item -Recurse
    Get-ChildItem -Path 'HKCU:\Software\Classes\vscode*' | Remove-Item -Recurse
    Remove-Item -Path 'HKCU:\SOFTWARE\Classes\*\shell\vscode' -Recurse
    Remove-Item -Path 'HKCU:\SOFTWARE\Classes\Applications\Code.exe' -Recurse

    $ErrorActionPreference = $PreviousErrorActionPreference
}

Write-Verbose -Message 'Declaring Function Set-VSCFileTypeCommand'
Function Set-VSCFileTypeCommand {
  [CmdletBinding()]
  # see https://msdn.microsoft.com/en-us/library/dd878260(VS.85).aspx
  # CommandPath and Arguments / Parameters should look something like: H:\Programs\VSCode\Code.exe --reuse-window  --user-data-dir H:\Programs\VSCode\data\user-data --extensions-dir H:\Programs\VSCode\data\extensions
  Param (
    [Parameter(Position=0)]
        [string]$ProgID = 'VSCode'
    ,
    [Parameter(Position=1)]
    [ValidateScript({Test-Path -Path (Resolve-Path -Path $PSItem)})]
        [string]$CommandPath = (Resolve-Path -Path ('{0}\vscode\app\code.exe' -f $HOME))
  )
  # Programmatically update the Windows "Default Program" for file types / extensions supported by VS Code

  <#
      Method 1: Old school
      https://technet.microsoft.com/en-us/library/ff687021.aspx
      https://superuser.com/questions/406985/programatically-associate-file-extensions-with-application-on-windows
      cmd /c assoc .ps1

      Method 2: Registry 'hack'
      Reminder: "HKEY_CLASSES_ROOT" is an alias to HKLM:\SOFTWARE\Classes

      HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts
      See also:
      Programmatic Identifiers
      https://msdn.microsoft.com/en-us/library/windows/desktop/cc144152(v=vs.85).aspx
  #>

    $command = Get-ChildItem -LiteralPath Registry::HKEY_CURRENT_USER\SOFTWARE\Classes | where {$_.PSPath -like "*vscode*"} | foreach {(Get-Item -LiteralPath (Join-Path -Path $_.PSPath -ChildPath 'shell\open\command')).GetValue('') ; pause}
    

    Write-Verbose -Message 'Declaring Function Test-UserFileType'
    function Test-UserFileType {
        Param (
            [Parameter(Position=0)]
            [string]$FileType = '.ps1'
        )

        $UserFileTypeSet = $false

        Write-Verbose -Message ('Testing $FileType: {0}' -f $FileType)

        Write-Verbose -Message ('Checking for registry key HKCU:\Software\Classes\{0}' -f $FileType)
        if (Test-Path -Path ('HKCU:\Software\Classes\{0}' -f $FileType)) {
            Write-Verbose -Message ('Detected HKCU:\Software\Classes\{0}' -f $FileType)
            try {
                Write-Verbose -Message ('Get-ItemProperty -Path "HKCU:\Software\Classes\{0}" -Name "(Default)"' -f $FileType)
                $default = (Get-ItemProperty -Path ('HKCU:\Software\Classes\{0}' -f $FileType) | Select-Object -Property '(default)').'(default)'
                $UserFileTypeSet = $true
            }
            catch {
                Write-Verbose -Message ('User FileType Description {0} NOT set' -f $FileType)
            #    $default = (Get-ItemProperty -Path "HKLM:\Software\Classes\$FileType" | Select-Object -Property '(default)').'(default)'
            #    Write-Verbose -Message ('Set-ItemProperty -Path "HKCU:\Software\Classes\{0}" -Name "(Default)" -Value {1}' -f $FileType,$default)
            #    $null = Set-ItemProperty -Path "HKCU:\Software\Classes\$FileType" -Name '(Default)' -Value $default -Force -ErrorAction SilentlyContinue
            #    $UserFileTypeSet = $true
            }
        }

        if ($UserFileTypeSet) {
            Write-Verbose -Message ('$UserFileTypeSet is $true')
            Write-Verbose -Message ('{0} FileType Description is {1}' -f $FileType, $default)
            return $true
        } else {
            return $false
        }
    }

    Write-Verbose -Message 'Declaring Function Test-UserProgID'
    function Test-UserProgID {
        Param (
            [Parameter(Position=0)]
            [string]$ProgID = 'VSCode'
        )

        $UserProgIDSet = $false

        Write-Verbose -Message ('Testing $ProgID: {0}' -f $ProgID)

        Write-Verbose -Message ('Checking for registry key HKCU:\Software\Classes\{0}' -f $ProgID)
        if (Test-Path -Path ('HKCU:\Software\Classes\{0}' -f $ProgID)) {
            Write-Verbose -Message ('Detected HKCU:\Software\Classes\{0}' -f $ProgID)
            try {
                Write-Verbose -Message ('Get-ItemProperty -Path "HKCU:\Software\Classes\{0}" -Name "(Default)"' -f $ProgID)
                $default = (Get-ItemProperty -Path ('HKCU:\Software\Classes\{0}' -f $ProgID) | Select-Object -Property '(default)').'(default)'
                $UserFileTypeSet = $true
            }
            catch {
                Write-Verbose -Message ('Get-ItemProperty -Path "HKLM:\Software\Classes\{0}" -Name "(Default)"' -f $ProgID)
                $default = (Get-ItemProperty -Path ('HKLM:\Software\Classes\{0}' -f $ProgID) | Select-Object -Property '(default)').'(default)'
                Write-Verbose -Message ('Set-ItemProperty -Path "HKCU:\Software\Classes\{0}" -Name "(Default)" -Value {1}' -f $ProgID,$default)
                $null = Set-ItemProperty -Path ('HKCU:\Software\Classes\{0}' -f $ProgID) -Name '(Default)' -Value $default -Force -ErrorAction SilentlyContinue
            }
            Write-Verbose -Message ('{0} ProgID is {1}' -f $ProgID, $default)
            $UserFileTypeSet = $true
        }

        Write-Verbose -Message ('Testing UserProgID: {0}' -f $ProgID)

        Write-Verbose -Message ('Checking for registry key HKCU:\Software\Classes\{0}' -f $ProgID)
        if (Test-Path -Path ('HKCU:\Software\Classes\{0}' -f $ProgID)) {
            Write-Verbose -Message ('Detected HKCU:\Software\Classes\{0}' -f $ProgID)
            $UserProgIDSet = $true
        }

        if ($UserFileTypeSet -and $UserProgIDSet) {
            Write-Verbose -Message ('$UserFileTypeSet and $UserProgIDSet are $true')
            return $true
        } else {
            return $false
        }
    }

    Write-Verbose -Message 'Declaring Function Add-UserProgID'
    function Add-UserProgID {
        Param (
            [Parameter(Position=0)]
            [string]$FileType = '.ps1'
            ,
            [Parameter(Position=1)]
            [string]$Description = 'PowerShell Script'
        )
        $ProgID_FTA = "$ProgID$FileType"
        Write-Verbose -Message ('$ProgID_FTA: {0}' -f $ProgID_FTA)
        New-Item -Path "HKCU:\Software\Classes\$ProgID_FTA" -Force

        Write-Verbose -Message ('Set-ItemProperty -Path "HKCU:\Software\Classes\{0}" -Name "(Default)" -Value {1}' -f $ProgID_FTA,$Description)
        $null = Set-ItemProperty -Path "HKCU:\Software\Classes\$ProgID_FTA" -Name '(Default)' -Value $Description -Force -ErrorAction SilentlyContinue

        Write-Verbose -Message ('New-Item -Path HKCU:\SOFTWARE\Classes\{0}\shell\open\command :: "{1}" "%1"' -f $ProgID_FTA,$CommandPath)
        $null = New-Item -Path "HKCU:\SOFTWARE\Classes\$ProgID_FTA\shell\open\command" -Force -ErrorAction SilentlyContinue
        $null = New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$ProgID_FTA\shell\open\command" -Name '(Default)' -PropertyType String -Value """$CommandPath"" ""%1"""  -Force -ErrorAction SilentlyContinue

        Write-Verbose -Message ('New-Item -Path HKCU:\SOFTWARE\Classes\{0}\shell\open\command :: "{1}" "%1"' -f $ProgID_FTA,$CommandPath)
        $null = New-Item -Path "HKCU:\SOFTWARE\Classes\$ProgID_FTA\shell\open\command" -Force -ErrorAction SilentlyContinue
        $null = New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$ProgID_FTA\shell\open\command" -Name '(Default)' -PropertyType String -Value """$CommandPath"" ""%1"""  -Force -ErrorAction SilentlyContinue

        # EditFlags = 0x00010004
        Write-Verbose -Message "New-ItemProperty -Path 'HKCU:\SOFTWARE\Classes\$ProgID_FTA' -Name 'EditFlags' -PropertyType DWORD -Value '0x00010004'"
        $null = New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$ProgID_FTA" -Name 'EditFlags' -PropertyType DWORD -Value '0x00010004'  -Force -ErrorAction SilentlyContinue

        # PerceivedType = "text"
        Write-Verbose -Message "New-ItemProperty -Path 'HKCU:\SOFTWARE\Classes\$ProgID_FTA' -Name 'PerceivedType' -PropertyType String -Value 'text'"
        $null = New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$ProgID_FTA" -Name 'PerceivedType' -PropertyType String -Value 'text'  -Force -ErrorAction SilentlyContinue
    }

    Write-Verbose -Message 'Declaring Function Add-OpenWithProgID'
    function Add-OpenWithProgID {
        Param (
            [Parameter(Mandatory,Position=0,HelpMessage='Specify File Type to add/update association.')]
            [ValidateNotNullorEmpty()]
            [string]
            $FileType,
            [Parameter(Mandatory,Position=1,HelpMessage='Specify ProgID to associate FileType with.')]
            [string]
            $OpenWithProgid
        )
        $ProgID_FTA = "$ProgID$FileType"
        Write-Verbose -Message ('$ProgID_FTA: {0}' -f $ProgID_FTA)

        # Check if the FileType has this $OpenWithProgid set
        $OpenWithProgidMatched = $false
        Get-Item -Path ('HKCU:\SOFTWARE\Classes\{0}\OpenWithProgids' -f $FileType) | ForEach-Object {
            Write-Verbose -Message ('OpenWithProgid: {0}' -f $PSItem.Property)
            if ($PSItem.Property -eq $OpenWithProgid) {
                $OpenWithProgidMatched = $true
            }
        }

        # If the FileType does not have this $OpenWithProgid, then we add it
        Write-Verbose -Message ('OpenWithProgidMatched: {0}' -f $OpenWithProgidMatched)
        if ($OpenWithProgidMatched) {
            Write-Verbose -Message ('OpenWithProgid {0} already set in the registry for FTA: {1}' -f $OpenWithProgid, $ProgID_FTA)
        } else {
            Write-Verbose -Message ('Adding OpenWithProgid {0} for FTA: {1}' -f $OpenWithProgid, $ProgID_FTA)
            Write-Debug -Message ('New-Item -Path HKCU:\SOFTWARE\Classes\{0}\OpenWithProgids\{1} = ' -f $ProgID_FTA, $OpenWithProgid)
            $null = New-Item -Path ('HKCU:\SOFTWARE\Classes\{0}\OpenWithProgids' -f $FileType) -Force -ErrorAction SilentlyContinue
            $null = New-ItemProperty -Path ('HKCU:\SOFTWARE\Classes\{0}\OpenWithProgids' -f $FileType) -Name $OpenWithProgid -Force -ErrorAction SilentlyContinue
        }
    }

# Before checking or changing file type OpenWith association, add essential ProgIDs
$CodeProgID = DATA {
    ConvertFrom-StringData -stringdata @'
    bashfile = Bash Script
    gitfile = Git
    JSONFile = JavaScript Configuration File
    kixfile = KIX Script
    luafile = LUA Script
    MOFfile = Managed Object File
    markdownfile = Markdown Document
    Perl.Module = Perl Module
    Perl.Script = Perl Script
    pyfile = Python Script
    shfile = Shell Script
    SQL.document = SQL document
    yamlfile = YAML Configuration File
'@
}

$CodeFileTypes = DATA {
    ConvertFrom-StringData -stringdata @'
    .bash = bashfile
    .bash_login = bashfile
    .bash_logout = bashfile
    .bash_profile = bashfile
    .bashrc = bashfile
    .bat = batfile
    .cmd = cmdfile
    .config = inifile
    .gitattributes = gitfile
    .gitconfig = gitfile
    .gitignore = gitfile
    .htm = HTTP
    .html = htmlfile
    .ini = inifile
    .json = JSONFile
    .kix = kixfile
    .lua = luafile
    .markdown = markdown.document
    .md = markdown.document
    .mdoc = markdown.document
    .mdown = markdown.document
    .mdtext = markdown.document
    .mdtxt = markdown.document
    .mdwn = markdown.document
    .mkd = markdown.document
    .mkdn = markdown.document
    .mof = MOFfile
    .pl = Perl.Script
    .pl6 = Perl.Script
    .pm = Perl.Module
    .pm6 = Perl.Module
    .profile = bashfile
    .properties = inifile
    .ps1 = Microsoft.PowerShellScript.1
    .psd1 = Microsoft.PowerShellData.1
    .psm1 = Microsoft.PowerShellModule.1
    .pssc = Microsoft.PowerShellSessionConfiguration.1
    .py = pyfile
    .sh = shfile
    .sql = sql.document
    .txt = txtfile
    .vbs = vbsfile
    .xaml = Windows.XamlDocument
    .xml = xmlfile
    .yaml = yamlfile
    .yml = yamlfile
'@
}

    foreach ($ext in $CodeFileTypes.Keys) {
        if (Test-UserProgID -FileType $ext) {
            Write-Verbose -Message 'ProgID for FileType {0} Description already defined'
        } else {
            Write-Verbose -Message ('Add-UserProgID -FileType {0} -Description {1}' -f $ext, ('{0}' -f $CodeProgID.$($CodeFileTypes.$ext)))
            Add-UserProgID -FileType $ext -Description $($CodeProgID.$($CodeFileTypes.$ext))
        }

        $default = (Get-ItemProperty -Path ('HKCU:\SOFTWARE\Classes\{0}' -f "$ProgID$ext") | Select-Object -Property '(default)').'(default)'
        Write-Verbose -Message ('{0} (Default) Description is {1}' -f $ext,$default)
        if ($default -eq "$ProgID$ext") {
            # Current ProgID matches what we'd set it to
            Write-Verbose -Message ('ProgID for FileType {0} assigned to {1}{2}' -f $default, $ProgID, $ext)
        } else {
            # just add OpenWithProgIDs
            Write-Verbose -Message ('Add-OpenWithProgID -FileType {0} -OpenWithProgid {1}{2}' -f $ext, $ProgID, $ext)
            Add-OpenWithProgID -FileType $ext -OpenWithProgid $ProgID$ext
        }

        if ($VerbosePreference -ne 'SilentlyContinue') {
            Write-Verbose -Message ('Detected $VerbosePreference is {0}' -f $VerbosePreference)
            Write-Verbose -Message 'Start-Sleep -Seconds 5'
            Start-Sleep -Seconds 5
        }
    }

    <#
        #pseudo-code for these FTA

        foreach ($ext in $CodeFileTypes)
        if exist {
            # just add OpenWithProgIDs
            HKCU:\SOFTWARE\Classes\$ext\OpenWithProgids\$VSCode.ProgID
        } else {
            HKCU:\SOFTWARE\Classes\$ext\
                (default) = $ext.Value
      EditFlags = 0x00010004
                PerceivedType = "text"
    }

        #pseudo-code for each ProgID / $ext.Value
        * * https://msdn.microsoft.com/en-us/library/windows/desktop/bb762506(v=vs.85).aspx

        if test-path HKCU:\SOFTWARE\Classes\$ext.Value {
            show (default) description
            compare \shell\open\command
        } else {
            HKCU:\SOFTWARE\Classes\$key.Name\(default) = $key.Value
            HKCU:\SOFTWARE\Classes\$key.Name\shell\open\command = $key.Value
        }

        foreach ($ext in $CodeFileTypes.Keys) {
            $RegPath = ('HKCU:\SOFTWARE\Classes\{0}' -f $ext)
            if (Test-Path -Path $RegPath) {
                $default = (Get-ItemProperty -Path $RegPath | Select-Object -Property '(default)').'(default)'
                Write-Verbose -Message ('{0} (Default) Description is {1}' -f $RegPath,$default)
                if ($default -eq "$ProgID$ext") {
                    # Current ProgID matches what we'd set it to
                    Write-Verbose -Message ('ProgID for FileType {0} assigned to {1}' -f $default, "$ProgID$ext")
                } else {
                    # just add OpenWithProgIDs
                    Write-Verbose -Message ('Add-OpenWithProgID -FileType {0} -OpenWithProgid {1}' -f $ext, "$ProgID$ext")
                    Add-OpenWithProgID -FileType $ext -OpenWithProgid $ProgID$ext
                }
            }
        }

    <#
      Write-Verbose -Message ' > (line break)'
      Write-Verbose -Message ' > (line break)'
      Write-Verbose -Message ' > (line break)'
      Write-Warning -Message " !`t!`t!`n`t> > > `n`t> > > Restarting Windows Explorer to refresh your file type associations.`n`t> > > "
      '10 ...'
      Start-Sleep -Seconds 1
      '9 ...'
      Start-Sleep -Seconds 1
      '8 ...'
      Start-Sleep -Seconds 1
      '7 ...'
      Start-Sleep -Seconds 1
      '6 ...'
      Start-Sleep -Seconds 1
      '5 ...'
      Start-Sleep -Seconds 1
      '4 ...'
      Start-Sleep -Seconds 1
      '3 ...'
      Start-Sleep -Seconds 1
      '2 ...'
      Start-Sleep -Seconds 1
      '1 ...'
      Start-Sleep -Seconds 1
      Get-Process -Name explorer* | Stop-Process
    #>
  #Start-Sleep -Seconds 1
  ('Opening Explorer to {0}' -f $HOME)
  Start-Sleep -Seconds 1
  & "$env:windir\explorer.exe" $HOME
}
