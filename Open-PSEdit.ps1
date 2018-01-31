#!/usr/local/bin/powershell
#Requires -Version 3
[CmdletBinding()]
Param()
#Set-StrictMode -Version latest

# Ensure this script is dot-sourced, to get access to it''s contained functions

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
        # $CallStack | Select Position, ScriptName, Command | format-list # FunctionName, ScriptLineNumber, Arguments, Location
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

# Detect older versions of PowerShell and add in new automatic variables for more cross-platform consistency
if (-not ((Get-Variable -Name IsWindows -ErrorAction Ignore) -eq $true)) { 
    $IsWindows = $false
    if ($Host.Version.Major -le 5) {
        $IsWindows = $true
    }
}

if ($IsWindows) {
    $hostOS = 'Windows'
    $hostOSCaption = $((Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption).Caption) -replace 'Microsoft ', ''
    # Check admin rights / role; same approach as Test-LocalAdmin function in Sperry module
    $IsAdmin = (([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
}

# dot-source script file containing Add-PATH and related helper functions
#$RelativePath = Split-Path -Path (Resolve-Path -Path $MyScriptInfo.CommandPath) -Parent
#Write-Verbose -Message 'Initializing .\Edit-Path.ps1'
#. $(Join-Path -Path (Split-Path -Path (Resolve-Path -Path $MyScriptInfo.CommandPath) -Parent) -Childpath 'Edit-Path.ps1')

# Declare path where the functions below should look for git.exe
# If/when needed, this path will be added to $Env:Path as a dependency of VS Code and some extensions
$GitPath = 'R:\IT\Microsoft Tools\VSCode\GitPortable\cmd'

Write-Verbose -Message 'Declaring Function Get-PSEdit'
Function Get-PSEdit {
    Write-Verbose -Message 'Getting environment variable PSEdit'
    if ($Env:PSEdit) {
        return $Env:PSEdit
    } else {
        Write-Output -InputObject "Env:PSEdit is Undefined.`nRun Assert-PSEdit to declare or detect Path to available editor."
    }
}

Write-Verbose -Message 'Declaring Function Assert-PSEdit'
Function Assert-PSEdit {
    [CmdletBinding(ConfirmImpact='High',SupportsShouldProcess=$true)]
    Param (
        [Parameter(Position=0)]
        [ValidateScript({Test-Path -Path (Resolve-Path -Path $PSItem)})]
        [String]
        $Path = '$HOME\vscode\app\bin\code.cmd'
    )

    if ($Env:PSEdit) {
        if (Test-Path -Path $Env:PSEdit) {
            Write-Verbose -Message ('Preparing to update / override $Env:PSEdit {0} with {1}' -f $Env:PSEdit, $Path)
        } else {
            Write-Verbose -Message "`$Env:PSEdit is currently pointed at invalid Path: $Env:PSEdit"
        }
    }

    Write-Verbose -Message 'Seeking an available editor: either VS Code or ISE'
    $vscode = $null
    if ($IsWindows) {
        Write-Verbose -Message 'Detected Windows OS. Checking for  a match to ''VS Code'' in PATH'
        # Look for default install path of "...\Microsoft VS Code\..." in Environment PATH
        if ($Env:PATH -split ';' | select-string -Pattern 'VS Code') {
            Write-Verbose -Message 'An entry matching ''VS Code'' was found in the PATH variable'
            $vscode = Join-Path -Path ($Env:PATH -split ';' | select-string -Pattern 'VS Code' | Select-Object -Property Line).Line -ChildPath 'code.cmd' -Resolve
            Write-Verbose -Message ('Derived {0} from the PATH' -f $vscode)
        } else {
            Write-Verbose -Message 'VS Code NOT found ... Checking if ISE is available'
            $PSISE = Join-Path -Path $PSHOME -ChildPath 'powershell_ise.exe' -Resolve
            if (Test-Path -Path $PSISE -PathType Leaf) {
                Write-Verbose -Message 'Detected PS ISE is installed.'
            }
        }
    } else {
        Write-Verbose -Message 'Detected NOT Windows OS. Checking for result from ''which code'''
        # Ask host os for the path to Visual Studio Code (via which binary/exe)
        $ErrorActionPreference = 'SilentlyContinue'
        $vscode = Resolve-Path -Path (which code) -ErrorAction SilentlyContinue
        $ErrorActionPreference = 'Continue'
    }

    if ($null -ne $vscode) {
        Write-Verbose -Message "Setting `$Env:PSEdit to `$vscode: $vscode"
        $Env:PSEdit = $vscode
    } elseif (Test-Path -Path $Path -PathType Leaf -ErrorAction SilentlyContinue) {
            $Path = Resolve-Path -Path $Path
            Write-Verbose -Message "Setting `$Env:PSEdit to Path (Parameter): $Path"
            $Env:PSEdit = $Path
            if ($IsWindows -and ($Path -like '*\\code\.')) {
                # Check and update $Env:PATH to include path to code; some code extensions look for code in the PATH
                Write-Verbose -Message "Adding $(Split-Path -Path $Env:PSEdit -Parent -Resolve) to `$Env:PATH"
                # Send output from Add-EnvPath to Null, so we don't have to read $Env:Path in the console
                # No need for pre-processing, as Add-EnvPath function handles attempts to add duplicate path statements
                $null = Add-EnvPath -Path (Split-Path -Path $Env:PSEdit -Parent -Resolve)
                # Check and conditionally update File Type Associations, to make it easier to open supported file types in VS Code, from Windows Explorer
      <#          if (Test-FileTypeAssociation) {
                    Write-Verbose -Message 'Expected file types are associated with VS code'
                } else {
                    Write-Verbose -Message 'Associating specified file types with VS code'
                    Add-FileType
                }
      #>
            }
    } elseif ($PSISE) {
        Write-Verbose -Message "Setting `$Env:PSEdit to $PSISE"
        $Env:PSEdit = $PSISE
    }

    return $Env:PSEdit
}

Write-Verbose -Message 'Declaring Function Test-FileTypeAssociation'
Function Test-FileTypeAssociation {
    [CmdletBinding()]
    Param (
        [Parameter(Position=0)]
        [string]$ProgID = 'vscode'
        ,
        [Parameter(Position=1)]
        [string]$Description = 'code file'
    )
    $ErrorActionPreference = 'SilentlyContinue'
    $Answer = (Get-ItemProperty -Path "HKCU:\Software\Classes\$ProgID" -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
    Write-Verbose -Message "ProgID $ProgID is associated as '$Answer'"
    $ErrorActionPreference = 'Continue'
    if ($Answer -eq $Description) {
        return $true
    } else {
        return $false
    }
}

Write-Verbose -Message 'Declaring Function Add-VSCFileTypeAssociation'
Function Add-VSCFileTypeAssociation {
  [CmdletBinding(ConfirmImpact='High',SupportsShouldProcess=$true)]
  # see https://msdn.microsoft.com/en-us/library/dd878260(VS.85).aspx
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

    # $CodeFileTypes = @('.bash','.bashrc','.bash_login','.bash_logout','.bash_profile','.bat','.cmd','.coffee','.config','.css','.gitattributes','.gitconfig','.gitignore','.go','.htm','.html','.ini','.js','.json','.lua','.kix','.markdown','.md','.mdoc','.mdown','.mdtext','.mdtxt','.mdwn','.mkd','.mkdn','.pl','.pl6','.pm','.pm6','.profile','.properties','.ps1','.psd1','.psgi','.psm1','.py','.sh','.sql','.t','.tex','.ts','.txt','.vb','.vbs','.xaml','.xml','.yaml','.yml','.zsh')

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
                $default = (Get-ItemProperty -Path "HKCU:\Software\Classes\$FileType" | Select-Object -Property '(default)').'(default)'
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
                $default = (Get-ItemProperty -Path "HKCU:\Software\Classes\$ProgID" | Select-Object -Property '(default)').'(default)'
                $UserFileTypeSet = $true
            }
            catch {
                Write-Verbose -Message ('Get-ItemProperty -Path "HKLM:\Software\Classes\{0}" -Name "(Default)"' -f $ProgID)
                $default = (Get-ItemProperty -Path "HKLM:\Software\Classes\$ProgID" | Select-Object -Property '(default)').'(default)'
                Write-Verbose -Message ('Set-ItemProperty -Path "HKCU:\Software\Classes\{0}" -Name "(Default)" -Value {1}' -f $ProgID,$default)
                $null = Set-ItemProperty -Path "HKCU:\Software\Classes\$ProgID" -Name '(Default)' -Value $default -Force -ErrorAction SilentlyContinue
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
            [Parameter(Position=0)]
            [ValidateNotNullorEmpty()]
            [string]
            $FileType,
            [Parameter(Position=1)]
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

# Before checking or changing file type OpenWith assocation, add essential ProgIDs
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
            Write-Verbose -Message ('Add-UserProgID -FileType {0} -Description {1}' -f $ext, "$($CodeProgID.$($CodeFileTypes.$ext))")
            Add-UserProgID -FileType $ext -Description $($CodeProgID.$($CodeFileTypes.$ext))
        }
        
        $default = (Get-ItemProperty -Path ('HKCU:\SOFTWARE\Classes\{0}' -f "$ProgID$ext") | Select-Object -Property '(default)').'(default)'
        Write-Verbose -Message ('{0} (Default) Description is {1}' -f $ext,$default)
        if ($default -eq "$ProgID$ext") {
            # Current ProgID matches what we'd set it to
            Write-Verbose -Message ('ProgID for FileType {0} assigned to {1}' -f $default, "$ProgID$ext")
        } else {
            # just add OpenWithProgIDs
            Write-Verbose -Message ('Add-OpenWithProgID -FileType {0} -OpenWithProgid {1}' -f $ext, "$ProgID$ext")
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
  "Opening Explorer to $HOME"
  Start-Sleep -Seconds 1
  & "$env:windir\explorer.exe" $HOME
}

Write-Verbose -Message 'Declaring Function Initialize-Git'
Function Initialize-Git {
    [CmdletBinding(SupportsShouldProcess)]
    param (
      [parameter(Mandatory,
          HelpMessage='Specify the path to git.exe', 
          ValueFromPipeline,
          Position = 0)]
        [Alias('Folder')]
      [String]$Path
  )

    if (($null -ne $Path) -and (Test-Path -Path $Path -PathType Container)) {
        $gitdir = Resolve-Path -Path $Path
    } else {
        Write-Warning -Message "Encountered error validating folder path $Path"
    }

    if (Get-Variable -Name gitdir -ErrorAction Ignore) {
        # Check and update $Env:PATH to include path to code; some code extensions look for code in the PATH
        Write-Verbose -Message "Adding (git) $gitdir to `$Env:PATH"
        # Send output from Add-EnvPath to Null, so we don't have to read $Env:Path in the console
        (Add-EnvPath -Path $gitdir) -split ';'
        $Env:GIT_DIR = $gitdir

        Write-Warning -Message "Add-EnvPath -Path $gitdir may not have succeeded."
        Write-Verbose -Message "`$Env:PATH += ;$gitdir"
        $Env:PATH += ";$gitdir"

        if ($Env:PATH -split ';' -contains $gitdir) {
            return $True # $gitdir
        } else {
            Write-Warning -Message "Git directory $Path was not properly added to the PATH"
            return $false
        }
    } else {
        Write-Verbose -Message '-Path to GIT_DIR either not specified or Path not valid'
    }
}
New-Alias -Name Init-Git -Value Initialize-Git -Scope Global -Force

Write-Verbose -Message 'Declaring Function Open-PSEdit'
function Open-PSEdit {
    <#
        Visual Studio Code
        Usage: code.exe [options] [paths...]

        Options:
        -d, --diff                  Open a diff editor. Requires to pass two file
                                    paths as arguments.
        -g, --goto                  Open the file at path at the line and column (add
                                    :line[:column] to path).
        --locale <locale>           The locale to use (e.g. en-US or zh-TW).
        -n, --new-window            Force a new instance of Code.
        -p, --performance           Start with the 'Developer: Startup Performance'
                                    command enabled.
        -r, --reuse-window          Force opening a file or folder in the last active
                                    window.
        --user-data-dir <dir>       Specifies the directory that user data is kept
                                    in, useful when running as root.
        --verbose                   Print verbose output (implies --wait).
        -w, --wait                  Wait for the window to be closed before
                                    returning.
        --extensions-dir <dir>      Set the root path for extensions.
        --list-extensions           List the installed extensions.
        --show-versions             Show versions of installed extensions, when using
                                    --list-extension.
        --install-extension <ext>   Installs an extension.
        --uninstall-extension <ext> Uninstalls an extension.
        --disable-extensions        Disable all installed extensions.
        --disable-gpu               Disable GPU hardware acceleration.
        -v, --version               Print version.
        -h, --help                  Print usage.

        Potential enhancements, as examples of code.exe / code-insiders.exe parameters
        --install-extension guosong.vscode-util --install-extension ms-vscode.PowerShell --install-extension Shan.code-settings-sync --install-extension wmaurer.change-case --install-extension DavidAnson.vscode-markdownlint
        --install-extension LaurentTreguier.vscode-simple-icons --install-extension seanmcbreen.Spell --install-extension mohsen1.prettify-json --install-extension ms-vscode.Theme-MarkdownKit 
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Position=0)]
        [array]
        $ArgumentList = $args
    )
    
    if (-not [bool]($Env:PSEdit)) {
        # If path to code.cmd is not yet known, use the supporting function Assert-PSEdit to establish it
        Write-Verbose -Message '$Env:PSEdit is not yet defined. Invoking Assert-PSEdit.'
        Assert-PSEdit
    }

    $ArgsArray = New-Object -TypeName System.Collections.ArrayList

    if ($Env:PSEdit -Like '*\code*') {
        Write-Verbose -Message '$Env:PSEdit -Like "*code*"; adding VS Code arguments'
        # Define 'default' Options, to pass to code
        $ArgsArray.Add('--skip-getting-started')
        $ArgsArray.Add("--user-data-dir $(Join-Path -Path $HOME -Childpath 'vscode')")
        $ArgsArray.Add("--extensions-dir $(Join-Path -Path $HOME -Childpath 'vscode\extensions')")
        # also add --reuse-window parameter, unless --new-window or it's alias -n were set in @args
        if (($ArgumentList -notcontains '--new-window') -and ($ArgumentList -notcontains '-n')) {
            $ArgsArray.Add('--reuse-window')
        }
    <#  if (-not (Test-FileTypeAssociation)) {
            Add-FileTypeAssociation -ProgID 'vscode' -CommandPath $Env:PSEdit
        } #>
    }

    if ($Env:PSEdit -Like '*Microsoft VS Code*') {
        # If Code appears to be installed, as signalled by \Microsoft VS Code\ in it's path, then let it use default user-data-dir and extensions-dir
        $ArgsArray.Remove("--user-data-dir $(Join-Path -Path $HOME -Childpath 'vscode')")
        $ArgsArray.Remove("--extensions-dir $(Join-Path -Path $HOME -Childpath 'vscode\extensions')")
    }

    # While we're at it, double-check git is available via PATH, for use from within VS Code
    # See ..\GitPortable\README.portable.md
    # set gitdir=c:\portablegit
    # set path=%gitdir%\cmd;%path%
    # usage: git [--version] [--help] [-C <path>] [-c name=value]
    #         [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]
    #         [-p | --paginate | --no-pager] [--no-replace-objects] [--bare]
    #         [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]
    #         <command> [<args>]
    if ($Env:PATH -notlike '*GitPortable\cmd*') {

        if (Test-Path -Path $GitPath) {
            Write-Verbose -Message "Initialize-Git -Path '$GitPath'"
            Initialize-Git -Path "$GitPath"
            # Derive .gitconfig path, then 'fix' the delimiter (swap from \ to /)
            $GitConfigPath = $((Join-Path -Path $HOME -ChildPath 'vscode\.gitconfig') -replace '\\','/')
            Write-Verbose -Message "Setting `$Env:GIT_CONFIG to $GitConfigPath"
            $Env:GIT_CONFIG = $GitConfigPath
            Write-Verbose -Message 'Setting $Env:GIT_CONFIG_NOSYSTEM = 1'
            $Env:GIT_CONFIG_NOSYSTEM = '1'
            Write-Verbose -Message '& git config credential.helper wincred'
            & "$env:GIT_DIR\git.exe" config credential.helper wincred

            Write-Verbose -Message '& git --version'
            & "$env:GIT_DIR\git.exe" --version
            if (!$?) {
                Write-Warning -Message 'git --version returned an error, likely because git was not found in PATH. Suggest manually modifying PATH to support git before re-opening VS Code'
            } else {
                Write-Verbose -Message "To review your git configuration(s), run 'git config --list --show-origin --path'"
            }
        } else {
            Write-Verbose -Message "Failed to validate `$GitPath: $GitPath"
        }
    }

    if ($Args -or $ArgumentList) {
        # sanitize passed parameters ?
        Write-Verbose -Message 'Processing $args.'
        foreach ($token in $ArgumentList) {
            Write-Debug -Message "Processing `$args token '$token'"
            # TODO Enhance Advanced function with parameter validation to match code.cmd / code.exe
            # Check for unescaped spaces in file path arguments
            if ($token -notlike ' ') {
                Write-Verbose -Message "Check `$token for spaces"
                if (Test-Path -Path $token) {
                    Write-Debug -Message "Wrapping  `$args token (path) $token with double quotes"
                    $token = """$token"""
                } else {
                    Write-Debug -Message "`$args token $token failed Test-Path, so NOT wrapping with double quotes"
                    $token = $token
                }
            # } else {
            #     $token = $token
            }
            Write-Verbose -Message "Adding $token to `$ArgsArray"
            $ArgsArray.Add($token)
        }
        Write-Verbose -Message "Results of processing `$args: $ArgsArray"
    }
    Write-Output -InputObject "Launching $Env:PSEdit $ArgsArray`n"
    if ($ArgsArray) {
        # Pass non-null $ArgsArray to -ArgumentList
        Start-Process -NoNewWindow -FilePath $Env:PSEdit -ArgumentList $ArgsArray
    } else {
        # Skip -ArgumentList
        Start-Process -NoNewWindow -FilePath $Env:PSEdit
    }
}

New-Alias -Name psedit -Value Open-PSEdit -Scope Global -Force

# Conditionally restore this New-Alias invocation, with a check for 'VS Code' in Env:PATH
New-Alias -Name Code -Value Open-PSEdit -Scope Global -Force
