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

# Declare path where the functions below should look for git.exe
# If/when needed, this path will be added to $Env:Path as a dependency of VS Code and some extensions
if (Test-Path -Path Env:myPSHome -ErrorAction SilentlyContinue) {
    Set-Variable -Name GitPath -Value (Join-Path -Path $myPSHome -ChildPath 'Resources\GitPortable\cmd') -Option AllScope
}

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

Write-Verbose -Message 'Declaring Function Get-PSEdit'
Function Get-PSEdit {
  <#
      .SYNOPSIS
          Get-PSEdit returns the path value of the currently configured $Env:PSEdit variable.
      .DESCRIPTION
          Get-PSEdit returns the path value of the currently configured $Env:PSEdit variable.
	      The $Env:PSEdit variable points to the path of the currently configured PowerShell editor, such as ISE or VScode.
      .EXAMPLE
          .> Get-PSEdit

	      C:\Program Files\Microsoft VS Code\bin\code.cmd
  #>


    Write-Verbose -Message 'Getting environment variable PSEdit'
    if ($Env:PSEdit) {
        return $Env:PSEdit
    } else {
        Write-Output -InputObject "Env:PSEdit is Undefined.`nRun Assert-PSEdit to declare or detect Path to available editor."
    }
}

Write-Verbose -Message 'Declaring Function Assert-PSEdit'
Function Assert-PSEdit {
    Param (
        [Parameter(Position=0)]
        [ValidateScript({Test-Path -Path (Resolve-Path -Path $PSItem)})]
        [String]
        $Path = (Join-Path -Path $HOME -ChildPath 'Programs\VSCode\code.exe' -Resolve)
    )

    if (Test-Path -Path Env:PSEdit) {
        if (Test-Path -Path $Env:PSEdit) {
            Write-Verbose -Message ('Preparing to update / override $Env:PSEdit {0} with {1}' -f $Env:PSEdit, $Path)
        } else {
            Write-Verbose -Message ('$Env:PSEdit is currently pointed at invalid Path: ''{0}''' -f $Env:PSEdit)
        }
    }

    Write-Verbose -Message 'Seeking an available editor: either VS Code or ISE'
    $vscode = $null
    if ($IsWindows) {
        Write-Verbose -Message 'Detected Windows OS. Checking for  a match to ''VS Code'' in PATH'
        # Look for default install path of "...\Microsoft VS Code\..." in Environment PATH
        if ($Env:PATH -split ';' | select-string -Pattern 'VS Code') {
            Write-Verbose -Message 'An entry matching ''VS Code'' was found in the PATH variable'
            $vscode = Join-Path -Path ($Env:PATH -split ';' | Select-String -Pattern 'VS Code' | Select-Object -Unique -Property Line -First 1).Line -ChildPath 'code.cmd'
            Write-Verbose -Message ('Derived {0} from the PATH' -f $vscode)
        } else {
            Write-Verbose -Message 'VS Code NOT found ... Checking if ISE is available'
            $PSISE = Join-Path -Path $PSHOME -ChildPath 'powershell_ise.exe'
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

    $Env:PSEdit = $null
    if ($null -ne $vscode) {
        Write-Verbose -Message ('Setting $Env:PSEdit to $vscode: ''{0}''' -f $vscode)
        $Env:PSEdit = $vscode
    } elseif (Test-Path -Path $Path -PathType Leaf -ErrorAction SilentlyContinue) {
            $Path = Resolve-Path -Path $Path
            Write-Verbose -Message ('Setting $Env:PSEdit to Path (Parameter): ''{0}''' -f $Path)
            $Env:PSEdit = $Path
            if ($IsWindows -and ($Path -match '\\code\.')) {
                # Check and update $Env:PATH to include path to code; some code extensions look for code in the PATH
                Write-Verbose -Message "Adding $(Split-Path -Path $Env:PSEdit -Parent -Resolve) to `$Env:PATH"
                # Send output from Add-EnvPath to Null, so we don't have to read $Env:Path in the console
                # No need for pre-processing, as Add-EnvPath function handles attempts to add duplicate path statements
                $null = Add-EnvPath -Path (Split-Path -Path $Env:PSEdit -Parent -Resolve).ToString()
                # (Over)Write the CURRENT_USER registry data value for Explorer right-click 'Open with Code'
                Write-Verbose -Message 'Register VSCode for all files (*)'
                Set-VSCodeRegistryCommand
                Write-Verbose -Message 'Register VSCode for PowerShell files (.ps1, .psd1, .psm1)'
                Set-VSCodeRegistryCommand -ProgID 'VSCode.ps1'
                Set-VSCodeRegistryCommand -ProgID 'VSCode.psd1'
                Set-VSCodeRegistryCommand -ProgID 'VSCode.psm1'
            }
    } elseif ($PSISE) {
        Write-Verbose -Message ('Setting $Env:PSEdit to (ISE): ''{0}''' -f $PSISE)
        $Env:PSEdit = $PSISE
    }
    Remove-Variable -Name vscode -ErrorAction SilentlyContinue
    Remove-Variable -Name PSISE -ErrorAction SilentlyContinue

    return $Env:PSEdit
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
        Write-Warning -Message ('Encountered error validating folder path {0}' -f $Path)
    }

    if (Get-Variable -Name gitdir -ErrorAction Ignore) {
        # Check and update $Env:PATH to include path to code; some code extensions look for code in the PATH
        Write-Verbose -Message ('Adding (git) {0} to $Env:PATH' -f $gitdir)
        # Send output from Add-EnvPath to Null, so we don't have to read $Env:Path in the console
        (Add-EnvPath -Path $gitdir) -split ';'

        Write-Warning -Message ('Add-EnvPath -Path {0} may not have succeeded.' -f $gitdir)
        Write-Verbose -Message ('$Env:PATH += ;{0}' -f $gitdir)
        $Env:PATH += ";$gitdir"

        if ($Env:PATH -split ';' -contains $gitdir) {
            return $True # $gitdir
        } else {
            Write-Warning -Message ('Git directory {0} was not properly added to the PATH' -f $Path)
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
    [CmdletBinding()]
    param (
        [Parameter(Position=0)]
        [string]
        $PSEdit = (Get-PSEdit),
        [Parameter(Position=0)]
        [array]
        $ArgumentList = $args
    )

    if (-not [bool]($Env:PSEdit)) {
        # If path to code.cmd is not yet known, use the supporting function Assert-PSEdit to establish it
        Write-Verbose -Message '$Env:PSEdit is not yet defined. Invoking Assert-PSEdit.'
        $PSEdit = Assert-PSEdit
    }

    # Make sure we've got a usable path to PSEdit before proceeding
    $null = Test-Path -Path $PSEdit -PathType Leaf -ErrorAction Stop

    $ArgsArray = New-Object -TypeName System.Collections.ArrayList

    # Inspect $PSEdit to see if it looks like a portable instance of Visual Studio Code
    if (($PSEdit -Like '*\code*') -and ($PSEdit -NotLike '*Microsoft VS Code*')) {
        Write-Verbose -Message '$PSEdit -Like "*code*"; adding VS Code arguments'

        # Support VS Code User installation edition
        $DataPath = Join-Path -Path (Split-Path -Path $PSEdit) -ChildPath 'data' -ErrorAction Ignore
        Write-Verbose -Message ('$DataPath is {0}' -f $DataPath)
        if (Test-Path -Path $DataPath -IsValid) {
            Write-Verbose -Message '$ArgsArray.Add(''--skip-getting-started'')'
            $null = $ArgsArray.Add('--skip-getting-started')
        } else {
            Write-Verbose -Message '\data\ folder not found - VS Code will start in Getting Started mode'
        }

        Write-Verbose -Message '$ArgsArray.Add(''--user-data-dir $DataPath\user-data'')'
        $null = $ArgsArray.Add('--user-data-dir {0}' -f (Join-Path -Path $DataPath -Childpath 'user-data'))
        Write-Verbose -Message '$ArgsArray.Add(''--extensions-dir $DataPath\extensions'')'
        $null = $ArgsArray.Add('--extensions-dir {0}' -f (Join-Path -Path $DataPath -Childpath 'extensions'))

        # also add --reuse-window parameter, unless --new-window or it's alias -n were set in @args
        if (($ArgumentList -notcontains '--new-window') -and ($ArgumentList -notcontains '-n')) {
            $null = $ArgsArray.Add('--reuse-window')
            Write-Verbose -Message '$ArgsArray.Add(''--reuse-window'')'
        }
        <#  if (-not (Test-FileTypeAssociation)) {
            Add-FileTypeAssociation -ProgID 'vscode' -CommandPath $PSEdit
        } #>
        # Is this version of VS Code current?
        Write-Verbose -Message 'Compare-PSEdit'
        Compare-PSEdit
    }
    <#
     if ($PSEdit -Like '*Microsoft VS Code*') {
         # If Code appears to be installed, as signalled by \Microsoft VS Code\ in it's path, then let it use default user-data-dir and extensions-dir
         $null = $ArgsArray.Remove(('--user-data-dir {0}' -f (Join-Path -Path $HOME -Childpath 'vscode')))
         $null = $ArgsArray.Remove(('--extensions-dir {0}' -f (Join-Path -Path $HOME -Childpath 'vscode\extensions')))
 
         # Is this version of VS Code current?
         Compare-PSEdit
     }
    #>

    # While we're at it, double-check git is available via PATH, for use from within VS Code
    # See ..\GitPortable\README.portable.md
    # set gitdir=c:\portablegit
    # set path=%gitdir%\cmd;%path%
    # usage: git [--version] [--help] [-C <path>] [-c name=value]
    #         [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]
    #         [-p | --paginate | --no-pager] [--no-replace-objects] [--bare]
    #         [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]
    #         <command> [<args>]
    if ($Env:PATH -notlike '*Git*') {
        # Locate $GitPath and add it to $Env:PATH
        if (Get-Variable -Name GitPath -ErrorAction Ignore) {
            if (Test-Path -Path $GitPath) {
                Write-Verbose -Message ('Initialize-Git -Path ''{0}''' -f $GitPath)
                Initialize-Git -Path "$GitPath"
                # Derive .gitconfig path, then 'fix' the delimiter (swap from \ to /)
                $GitConfigPath = $((Join-Path -Path $HOME -ChildPath 'vscode\.gitconfig') -replace '\\','/')
                Write-Verbose -Message ('Setting $Env:GIT_CONFIG to {0}' -f $GitConfigPath)
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
                Write-Verbose -Message ('Failed to validate $GitPath: {0}' -f $GitPath)
            }
        } else {
            Write-Verbose -Message ('Variable $GitPath not defined.')
        }
    }

    # Redirect PSedit to the cmd file, for intended argument / parameter handling
    Write-Verbose -Message '$PSEdit = $PSEdit -replace \code\.exe,\bin\code.cmd'
    $PSEdit = $PSEdit -replace '\\code\.exe','\bin\code.cmd'
    Write-Verbose -Message ('$PSEdit is {0}' -f $PSEdit)

    if ($Args -or $ArgumentList) {
        # sanitize passed parameters ?
        Write-Verbose -Message 'Processing $args'
        foreach ($token in $ArgumentList) {
            Write-Verbose -Message ('Processing $args token ''{0}''' -f $token)
            # TODO Enhance Advanced function with parameter validation to match code.cmd / code.exe
            # Check for unescaped spaces in file path arguments
            if ($token -match '\s') {
                Write-Verbose -Message 'Check $token for spaces'
                if (Test-Path -Path $token) {
                    Write-Verbose -Message ('Wrapping $args token (path) {0} with double quotes' -f $token)
                    $token = ('"{0}"' -f $token) # """$token"""
                } else {
                    Write-Verbose -Message ('$args token {0} failed Test-Path, so NOT wrapping with double quotes' -f $token)
                    #$token = $token
                }
            }
            Write-Verbose -Message ('Adding {0} to $ArgsArray' -f $token)
            $null = $ArgsArray.Add($token)
        }
        Write-Verbose -Message ('Results of processing $args: {0}' -f $ArgsArray)
    }
    Write-Output -InputObject ('Launching {0} {1}' -f $PSEdit, $ArgsArray)
    if ($ArgsArray) {
        # Pass non-null $ArgsArray to -ArgumentList
        Start-Process -NoNewWindow -FilePath $PSEdit -ArgumentList $ArgsArray
    } else {
        # Skip -ArgumentList
        Start-Process -NoNewWindow -FilePath $PSEdit -ArgumentList '--help'
    }
}

New-Alias -Name psedit -Value Open-PSEdit -Scope Global -Force

# Conditionally restore this New-Alias invocation, with a check for 'VS Code' in Env:PATH
New-Alias -Name Code -Value Open-PSEdit -Scope Global -Force
