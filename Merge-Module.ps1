#requires -Version 3 -Module PSLogger
#========================================
# NAME      : Merge-Module.ps1
# LANGUAGE  : Windows PowerShell
# AUTHOR    : Bryan Dady
# DATE      : 06/12/2016
# COMMENT   : PowerShell script to automate kdiff3.exe
# EXAMPLE   : PS .\> .\Merge-Module.ps1 -SourcePath .\Modules\ProfilePal -TargetPath ..\GitHub\ProfilePal -MergePath 'H:\My Documents\WindowsPowerShell\Modules\ProfilePal'
#========================================
[CmdletBinding(SupportsShouldProcess)]
param ()
#Set-StrictMode -Version latest

#========================================
#Region MyScriptInfo
    Write-Verbose -Message '[Merge-Module] Populating $MyScriptInfo'
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
        Write-Verbose -Message "Getting PSCallStack [`$CallStack = Get-PSCallStack]"
        $Private:CallStack        = Get-PSCallStack | Select-Object -First 1
        $Private:MyScriptName     = $Private:CallStack.ScriptName
        $Private:MyCommand        = $Private:CallStack.Command
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
    # $Script:MyScriptInfo = New-Object -TypeName PSObject -Property $Private:properties
    New-Variable -Name MyScriptInfo -Value (New-Object -TypeName PSObject -Property $Private:properties) -Scope Local -Option AllScope -Force
    # Cleanup
    foreach ($var in $Private:properties.Keys) {
        Remove-Variable -Name ('My{0}' -f $var) -Force
    }

    $IsVerbose = $false
    if ('Verbose' -in $PSBoundParameters.Keys) {
        Write-Verbose -Message 'Output Level is [Verbose]. $MyScriptInfo is:'
        $MyScriptInfo
        Set-Variable -Name IsVerbose -Value $true -Option AllScope
    }
    Write-Verbose -Message '[Merge-Module] $MyScriptInfo populated'
#End Region

# Clean Up this script's Variables. When this script is loaded (dot-sourced), we clean up Merge-Module specific variables to ensure they're current when the next function is invoked
('DiffSettings', 'DiffTool', 'DiffToolArgs', 'MergeEnvironmentSet', 'MyCommand*', 'netPSHome', 'properties') | ForEach-Object {
    # Cleanup any Private Scope residue
    if (Get-Variable -Name $PSItem -Scope Private -ErrorAction Ignore) {
        Write-Verbose -Message ('Remove-Variable $Private:{0}' -f $PSItem)
        Remove-Variable -Name $PSItem -Scope Private
    } else {
        Write-Verbose -Message ('Variable $Private:{0} not found.' -f $PSItem)
    }
    # Cleanup any Local Scope residue
    if (Get-Variable -Name $PSItem -Scope Local -ErrorAction Ignore) {
        Write-Verbose -Message ('Remove-Variable $Local:{0}' -f $PSItem)
        Remove-Variable -Name $PSItem -Scope Local
    } else {
        Write-Verbose -Message ('Variable $Local:{0} not found.' -f $PSItem)
    }
    # Cleanup any Script Scope residue
    if (Get-Variable -Name $PSItem -Scope Script -ErrorAction Ignore) {
        Write-Verbose -Message ('Remove-Variable $Script:{0}' -f $PSItem)
        Remove-Variable -Name $PSItem -Scope Script
    } else {
        Write-Verbose -Message ('Variable $Script:{0} not found.' -f $PSItem)
    }
} # End Clean Up

# Declare shared variables, to be available across/between functions
#$SettingsFileName = 'Merge-Module.json'
New-Variable -Name SettingsFileName -Description 'Path to Merge-Module settings file' -Value 'Merge-Module.json' -Scope Local -Option AllScope -Force
New-Variable -Name DiffSettings -Description ('Settings, from {0}' -f $SettingsFileName) -Scope Local -Option AllScope -Force
New-Variable -Name MergeEnvironmentSet -Description 'Boolean indicating custom environmental variables are loaded / available' -Value $false -Scope Local -Option AllScope -Force

$Private:CompareDirectory = Join-Path -Path $(Split-Path -Path $PSCommandPath -Parent) -ChildPath 'Compare-Directory.ps1' -ErrorAction Stop
Write-Verbose -Message (' Dot-Sourcing {0}' -f $Private:CompareDirectory)
. $Private:CompareDirectory

# Get Merge-Module config from Merge-Module.json
Write-Verbose -Message 'Declaring Function Import-MergeSettings'
Function Import-MergeSettings {
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [switch]
        $ShowSettings
    )
    <#
        "`n # variables in Global scope #"
        get-variable -scope Global

        "`n # variables in Local scope #"
        get-variable -scope Local

        "`n # variables in Script scope #"
        get-variable -scope Script

        "`n # variables in Private scope #"
        get-variable -scope Private
    #>
    
    Write-Debug -Message ('$DSPath = Join-Path -Path $(Split-Path -Path {0} -Parent) -ChildPath {1}' -f $PSCommandPath, $SettingsFileName)
    
    $DSPath = Join-Path -Path $(Split-Path -Path $PSCommandPath -Parent) -ChildPath $SettingsFileName
    Write-Debug -Message ('$DiffSettings = (Get-Content -Path {0} ) -join "`n" | ConvertFrom-Json' -f $DSPath)

    try {
        $DiffSettings = (Get-Content -Path $DSPath) -join "`n" | ConvertFrom-Json -ErrorAction Stop
        Write-Verbose -Message 'Settings imported to $DiffSettings.' 
    }
    catch {
        throw ('[Import-MergeSettings]: Critical Error loading settings from from {0}' -f $DSPath)
    }

    if ($DiffSettings -and $ShowSettings) {
        $DiffSettings | Add-Member -NotePropertyName imported -NotePropertyValue (Get-Date -UFormat '%m-%d-%Y') -Force
        $DiffSettings | Add-Member -NotePropertyName SourcePath -NotePropertyValue $DSPath -Force

        if ($IsVerbose) {
            Write-Output -InputObject ' [Verbose] $DiffSettings:' | Out-Host
            Write-Output -InputObject $DiffSettings | Out-Host
        }
    }

} # end function Import-MergeSettings

Write-Verbose -Message 'Declaring Function Get-Environment'
function Get-Environment {
    [CmdletBinding(SupportsShouldProcess)]
    param ()

    if (Get-Variable -Name myPSLogPath -ErrorAction Ignore) {
        Write-Verbose -Message ('Logging previously initialized. $myPSLogPath: {0}' -f $myPSLogPath)
    } else {
        Write-Verbose -Message '[Bootstrap] Initialize PowerShell Custom Environment Variables.'
        # Load/invoke bootstrap
        if (Test-Path -Path (Join-Path -Path $myPSHome -ChildPath 'bootstrap.ps1')) {
            . (Join-Path -Path $myPSHome -ChildPath 'bootstrap.ps1')

            if (Get-Variable -Name 'myPS*' -ValueOnly -ErrorAction Ignore) {
                Write-Output -InputObject ''
                Write-Output -InputObject 'My PowerShell Environment:'
                Get-Variable -Name 'myPS*' | Format-Table
            } else {
                Write-Warning -Message 'Failed to enumerate My PowerShell Environment as should have been initialized by bootstrap script: {0}' -f ((Join-Path -Path $myPSHome -ChildPath 'bootstrap.ps1'))
            }
        } else {
            throw ('Failed to bootstrap: {0}\bootstrap.ps1' -f $myPSHome)
        }
        Write-Verbose -Message ('Logging initialized. $myPSLogPath: {0}' -f $myPSLogPath)
    }

    if ($myPSHome -match "$env:SystemDrive") {
        Write-Verbose -Message ('Set $localPSHome to {0}' -f $myPSHome)
        #$localPSHome = $myPSHome
        Set-Variable -Name localPSHome -Value $myPSHome -Scope Local
    } else {
        $localPSHome = Join-Path -Path $env:USERPROFILE -ChildPath '*Documents\WindowsPowerShell' -Resolve
        Set-Variable -Name localPSHome -Value $localPSHome -Scope Local
    }

    # If %HOMEDRIVE% does not match %SystemDrive%, then it's a network drive, so use that 
    if ($env:HOMEDRIVE -ne $env:SystemDrive) {
        if (Test-Path -Path $env:HOMEDRIVE) {
            $netPSHome = (Join-Path -Path $env:HOMEDRIVE -ChildPath '*\WindowsPowerShell' -Resolve)
            Write-Verbose -Message ('Set $netPSHome to {0}' -f $netPSHome)
            #$netPSHome = Join-Path -Path $env:HOMEDRIVE -ChildPath '*\WindowsPowerShell' -Resolve
            Set-Variable -Name netPSHome -Value $netPSHome -Scope Local
        } else {
            Write-Warning -Message 'Test-Path -Path $env:HOMEDRIVE: $false'
        }
    } else {
        Write-Warning -Message '($env:HOMEDRIVE -ne $env:SystemDrive): $false'
    }

    Set-Variable -Name MergeEnvironmentSet -Description 'Boolean indicating custom environmental variables are loaded / available' -Value $true
} # end function Get-Environment

Write-Verbose -Message 'Declaring Function Merge-Repository'
function Merge-Repository {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Mandatory = $true,HelpMessage='Specify path to the source repository',Position = 0)]
        [ValidateScript({Test-Path -Path $PSItem})]
        [Alias('SourcePath','A','file1')]
        [String]
        $Path = $null
        ,
        [Parameter(Mandatory = $true,HelpMessage='Specify path to the target repository',Position = 1)]
        [ValidateScript({Test-Path -Path $PSItem -IsValid})]
        [Alias('TargetPath','B','file2')]
        [String]
        $Destination = $null
        ,
        [Parameter(Position = 2)]
        [ValidateScript({Test-Path -Path $PSItem -IsValid})]
        [Alias('MergePath','C')]
        [String]
        $file3 = $null
        ,
        [Parameter(Position = 3)]
        [switch]
        $Recurse = $false
        ,
        [Parameter(Position = 4)]
        [array]
        $Filter = $null
    )
    # ======== SETUP ====================

    $ErrorActionPreference = 'SilentlyContinue'
    if ($DiffSettings -and ($DiffSettings.imported)) {
        Write-Verbose -Message '$DiffSettings instantiated.'
    } else {
        Write-Verbose -Message ('Reading configs from {0} to $DiffSettings' -f $SettingsFileName)
        Import-MergeSettings -ErrorAction Stop
    }
    Write-Verbose -Message (' # $DiffSettings: {0}' -f $DiffSettings | Format-Table)
    $ErrorActionPreference = 'Continue'

    if (-not (Get-Variable -Name MergeEnvironmentSet -ErrorAction Ignore)) {
        Write-Verbose -Message 'Load custom environment variables with Get-Environment function'
        Get-Environment
    }

    if (Get-Variable -Name '*PSHome' -ValueOnly -ErrorAction Ignore) {
        #Write-Output -InputObject 'My PowerShell Environment:'
        if ('Verbose' -in $PSBoundParameters.Keys) {
            Write-Verbose -Message 'Output Level is [Verbose]. "*PSHome" variables:'
            Get-Variable -Name '*PSHome' | Format-Table #| out-host
        }
    } else {
        Write-Warning -Message 'Failed to enumerate My PowerShell Environment as should have been initialized by Get-Environment function'
    }

    <# Delete ? $LogName = $MyScriptInfo.CommandName.Split('.')[0] #>
    # Build dynamic logging file path at ...\[My ]Documents\WindowsPowershell\log\[scriptname]-[rundate].log
    $logFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -UFormat '%Y%m%d')))
    Write-Output -InputObject '' | Tee-Object -FilePath $logFile -Append
    Write-Verbose -Message (' # Logging to {0}' -f $logFile)

    $RCLogFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-robocopy-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -UFormat '%Y%m%d')))
    
    # Resolve path to diff / merge tool
    Write-Verbose -Message ('Getting DiffTool.Path: {0}' -f $DiffSettings.DiffTool.Path)
    # $DiffTool = Resolve-Path -Path (Join-Path -Path (Split-Path -Path PSCommandPath -Parent) -ChildPath $DiffSettings.DiffTool.Path) -Relative
    $DiffTool = $ExecutionContext.InvokeCommand.ExpandString($DiffSettings.DiffTool.Path)
    
    if (Test-Path -Path $DiffTool -PathType Leaf) {
        Write-Verbose -Message ('Using diff tool: {0}' -f $DiffTool)
    } else {
        Write-Warning -Message ('Failed to resolve path to DiffTool (specified in Settings): {0}' -f $DiffTool)
        break
    }

    $DiffToolArgs = $DiffSettings.DiffTool.Options #| ForEach-Object -Process {"$($PSItem.Setting)=$($PSItem.Value)"})+''

    if ($Recurse) {
        $DiffToolArgs = "/r $DiffToolArgs"
    }

    # ======== BEGIN ====================
    Write-Verbose -Message ('{0} # Starting Merge-Repository -Path {1} -Destination {2} -file3 {3}' -f (Get-Date -Format g), $Path, $Destination, $file3) | Tee-Object -FilePath $logFile -Append
    
    Write-Debug -Message ('$DiffToolArgs: {0}' -f $DiffToolArgs) | Tee-Object -FilePath $logFile -Append
    # $ErrorActionPreference = 'Stop'
    Write-Debug -Message ('Test-Path -Path: {0}' -f $Path)
    try {
        $null = Test-Path -Path (Resolve-Path -Path $Path)
    }
    catch {
        Write-Output -InputObject ('Error was {0}' -f $_) | Tee-Object -FilePath $logFile -Append
        $line = $MyInvocation.ScriptLineNumber | Tee-Object -FilePath $logFile -Append
        Write-Output -InputObject ('Error was in Line {0}' -f $line) | Tee-Object -FilePath $logFile -Append
        Write-Output -InputObject 'file1 (A) not found; nothing to merge.' | Tee-Object -FilePath $logFile -Append
    }

    Write-Debug -Message ('Test-Path -Path (Destination): {0}' -f $Destination)
    try {
        $null = Test-Path -Path (Resolve-Path -Path $Destination)
    }
    catch {
        Write-Output -InputObject ('Error was {0}' -f $_) | Tee-Object -FilePath $logFile -Append
        $line = $MyInvocation.ScriptLineNumber
        Write-Output -InputObject ('Error was in Line {0}' -f $line) | Tee-Object -FilePath $logFile -Append
        Write-Output -InputObject 'file2 (B) not found; nothing to merge. Copying via Copy-Item.' | Tee-Object -FilePath $logFile -Append
        Copy-Item -Path $Path -Destination $Destination -Recurse -Confirm | Tee-Object -FilePath $logFile -Append
    }
    # $ErrorActionPreference = 'Continue'

    # To handle spaces in paths, without triggering ValidateScript errors against the functions defined parameters, we copy the function parameters to internal variables
    # file1 / 'A' = $SourcePath ; file2 / 'B' = $TargetPath ; file3 / 'C' = $MergePath
    $SourcePath = (Resolve-Path -Path $Path)
    if ($SourcePath.ToString().Contains(' ')) {
        Write-Debug -Message 'Wrapping $SourcePath with double-quotes'
        $SourcePath = ('"{0}"' -f $SourcePath.ToString())
    #} else {
    #    $SourcePath =  (Resolve-Path -Path $Path)
    }
    Write-Debug -Message ('Resolved $SourcePath is: {0}' -f $SourcePath)

    $TargetPath = (Resolve-Path -Path $Destination)
    if ($TargetPath.ToString().Contains(' ')) {
        Write-Debug -Message 'Wrapping $TargetPath with double-quotes'
        $TargetPath = ('"{0}"' -f $TargetPath.ToString())
    #} else {
    #    $TargetPath = $Destination
    }
    Write-Debug -Message ('Resolved $TargetPath is: {0}' -f $TargetPath)

    $MergePath = $false
    if ($file3) {
        $MergePath = (Resolve-Path -Path $file3)
        if ($MergePath.ToString().Contains(' ')) {
            Write-Debug -Message 'Wrapping `$MergePath with double-quotes'
            $MergePath = ('"{0}"' -f $MergePath.ToString())
        #} else {
        #    $MergePath = $file3
        }
        Write-Debug -Message ('Resolved $MergePath is: {0}' -f $MergePath)
    }

    # ======== PROCESS ==================
    #region Merge
    # Show what we're going to run on the console, then actually run it.
    if ($DiffTool -and $SourcePath -and $TargetPath) {
        if ($MergePath) {
            Write-Verbose -Message ('Detected MergePath : {0}' -f $MergePath)
            Write-Verbose -Message ('{0} {1} {2} --output {3} {4}' -f $DiffTool, $SourcePath, $TargetPath, $MergePath, $DiffToolArgs)

            if ($PSCmdlet.ShouldProcess($SourcePath,$("Merge $SourcePath, $TargetPath, $MergePath"))) {
                Write-Debug -Message ('[DEBUG] {0} -ArgumentList {1} {2} --output {3} {4}' -f $DiffTool, $SourcePath, $TargetPath, $MergePath, $DiffToolArgs)
                Write-Output -InputObject "Merging $SourcePath `n: $TargetPath -> $MergePath" | Out-File -FilePath $logFile -Append
                Start-Process -FilePath $DiffTool -ArgumentList "$SourcePath $TargetPath $MergePath --output $MergePath $DiffToolArgs" -Wait | Tee-Object -FilePath $logFile -Append
            }

            # In a 3-way merge, kdiff3 only sync's with merged output file. So, after the merge is complete, we copy the final / merged output to the TargetPath directory.
            # Copy-Item considers double-quotes 'Illegal characters in path',  so we use the original $Destination, instead of $TargetPath
            Write-Verbose -Message ('Copy-Item -Path {0} -Destination {1} -Recurse -Confirm' -f $MergePath, (Split-Path -Path $Destination))
            # Copy-Item -Path $MergePath -Destination $(Split-Path -Path $Destination) -Recurse -Confirm

            if ($PSCmdlet.ShouldProcess($MergePath,$("Update $MergePath via Robocopy"))) {
            Write-Output -InputObject ('[Merge-Repository] Update {0} back to {1} (using Robocopy)' -f $MergePath, (Split-Path -Path $Destination)) | Tee-Object -FilePath $logFile -Append
            if ($null = Test-Path -Path $Destination -PathType Leaf) {
                $rcTarget = $(Split-Path -Path $Destination)
            } else {
                $rcTarget = $TargetPath
            }
            #Write-Verbose -Message ('robocopy.exe {0} {1} /L /MIR /TEE /MT /NP /TS /FP /DCOPY:T /DST /R:1 /W:1 /XF *.orig /NJH /NS /NC /NP /LOG+:{2}' -f $MergePath, $rcTarget, $RCLogFile)
            #Write-Output -InputObject ('robocopy {0} {1} /L /MIR /TEE /MT /NP /TS /FP /DCOPY:T /DST /R:1 /W:1 /XF *.orig /NJH /NS /NC /NP /LOG+:{2}' -f $MergePath, $rcTarget, $RCLogFile) | Out-File -FilePath $logFile -Append
            #& "$env:windir\system32\robocopy.exe" $MergePath $rcTarget /L /MIR /TEE /MT /NP /TS /FP /DCOPY:T /DST /R:1 /W:1 /XF *.orig /NJH /NS /NC /NP /LOG+:$RCLogFile
            Write-Output -InputObject ('[Merge-Repository] Updating container from {1} to {2}' -f $MergePath, $rcTarget) | Tee-Object -FilePath $logFile -Append
            Update-Repository -Path $MergePath -Destination $rcTarget -Confirm
            }
        } else {
                Write-Verbose -Message 'No MergePath; 2-way merge'
                Write-Verbose -Message "$DiffTool $SourcePath $TargetPath $DiffToolArgs"
                if ($PSCmdlet.ShouldProcess($SourcePath,$("Merge $SourcePath, $TargetPath"))) {
                    Write-Output -InputObject "Merging $SourcePath <-> $TargetPath" | Out-File -FilePath $logFile -Append
                    Start-Process -FilePath $DiffTool -ArgumentList "$SourcePath $TargetPath $DiffToolArgs" -Wait
                }
        }
    } else {
        throw 'No $DiffTool -and $SourcePath -and $TargetPath'
    }
    #EndRegion

    Write-Output -InputObject "`n$(Get-Date -Format g) # Ending Merge-Repository`n" | Tee-Object -FilePath $logFile -Append
    # ======== THE END ======================
    # Write-Output -InputObject '' | Tee-Object -FilePath $logFile -Append
} # end function Merge-Repository

Write-Verbose -Message 'Declaring Function Merge-MyPSFiles'
function Merge-MyPSFiles {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($DiffSettings -and ($DiffSettings.imported)) {
        Write-Verbose -Message ('{0} already instantiated.' -f $DiffSettings)
    } else {
        Write-Verbose -Message ('Read configs from {0} to $DiffSettings' -f $SettingsFileName)
        Import-MergeSettings
    }

    if ($MergeEnvironmentSet) {
        Write-Verbose -Message 'Merge-Module environmental variables already instantiated.'
    } else {
        Write-Verbose -Message 'Load custom environmental variables with Get-Environment function'
        Get-Environment
    }

    # Specifying the logFile name now explicitly updates the datestamp on the log file
    $logFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -UFormat '%Y%m%d')))
    Write-Output -InputObject '' | Tee-Object -FilePath $LogFile -Append
    Write-Output -InputObject (' # Logging to {0}' -f $LogFile)
    Write-Output -InputObject "$(Get-Date -Format g) # Starting Merge-MyPSFiles" | Tee-Object -FilePath $logFile -Append

    $MyRepositories = $DiffSettings | Select-Object -ExpandProperty RepositorySets
    Write-Verbose -Message ('MyRepositories: {0} ' -f $MyRepositories)
    
    ForEach ($repo in $MyRepositories) {
        Write-Debug -Message ('$repo.SourcePath: {0}' -f $repo.SourcePath)
        Write-Debug -Message ('$repo.TargetPath: {0}' -f $repo.TargetPath)
        $SourcePath = $ExecutionContext.InvokeCommand.ExpandString($repo.SourcePath)
        $TargetPath = $ExecutionContext.InvokeCommand.ExpandString($repo.TargetPath)
        Write-Verbose -Message ('$DriveName: {0}' -f $SourcePath)
        Write-Verbose -Message ('$PathRoot: {0}' -f $TargetPath)

        Write-Output -InputObject ('Merging {0}' -f $repo.Name) | Tee-Object -FilePath $logFile -Append
        Write-Verbose -Message ('[bool](Compare-Directory -ReferenceDirectory {0} -DifferenceDirectory {1} -ExcludeFile *.orig,.git*,.hg*,*.md,*.tests.*)' -f $SourcePath, $TargetPath)

        $Private:GoodToGo = $false
        # Test availability of SourcePath, and if missing, re-try Mount-Path function
        if (Test-Path -Path $SourcePath) {
            Write-Verbose -Message ('Confirmed source $SourcePath: {0} is available.' -f $SourcePath)
        } else {
            # Invoke Mount-Path function, from Sperry module, to map all user's drives
            Write-Warning -Message ('Source {0} is NOT available ... Running Mount-Path.' -f $SourcePath)
            Mount-Path
        }

        # Test availability of TargetPath, and if missing, re-try Mount-Path function
        if (Test-Path -Path (Split-Path -Path $TargetPath -Parent)) {
            Write-Verbose -Message ('Confirmed TargetPath (parent): {0} is available.' -f (Split-Path -Path ($TargetPath) -Parent))
            $Private:GoodToGo = $true
        } else {
            # Invoke Mount-Path function, from Sperry module, to map all user's drives
            Write-Warning -Message 'Target (parent) is NOT available ... Running Mount-Path.'
            Mount-Path
            # Re-Test availability of TargetPath, and if still missing, halt
            if (Test-Path -Path (Split-Path -Path $TargetPath -Parent)) {
                Write-Verbose -Message ('Confirmed TargetPath (parent): {0} is available.' -f (Split-Path -Path ($TargetPath) -Parent))
                $Private:GoodToGo = $true
            } else {
                # Invoke Mount-Path function, from Sperry module, to map all user's drives
                Write-Warning -Message 'TargetPath (parent) is still NOT available.'
            }
        }

        if ($Private:GoodToGo) {
            # Compare Directories (via contained file hashes) before sending to Merge-Repository
            Write-Verbose -Message ('Compare-Directory -ReferenceDirectory {0} -DifferenceDirectory {1}' -f $SourcePath, $TargetPath)
            $Private:DirectoryMatch = (Compare-Directory -ReferenceDirectory $SourcePath -DifferenceDirectory $TargetPath -ExcludeFile '*.orig','.git*','.hg*','*.md','*.tests.*')
            Write-Verbose -Message ('Compare-Directory results in Source/Destination Match? : {0}' -f $Private:DirectoryMatch)
            # if (Compare-Directory -ReferenceDirectory $($SourcePath) -DifferenceDirectory $($TargetPath) -ExcludeFile "*.orig",".git*",".hg*","*.md","*.tests.*") {
            if ($Private:DirectoryMatch) {
                Write-Verbose -Message 'No differences detected ... Skipping merge.'
            } else {
                Write-Verbose -Message 'Compare-Directory function indicates differences detected between repositories. Proceeding with Merge-Repository.'
                Write-Verbose -Message ('Merge-Repository -SourcePath {0} -TargetPath {1} -Recurse' -f $SourcePath, $TargetPath) | Tee-Object -FilePath $logFile -Append
                Merge-Repository -SourcePath $SourcePath -TargetPath $TargetPath -Recurse
            } # end if Compare-Directory
        } else {
            Write-Warning -Message 'Fatal Error validating source Path and target Destination'
        }
    }
    #EndRegion

    Write-Output -InputObject "`n$(Get-Date -Format g) # Ending Merge-MyPSFiles`n" | Tee-Object -FilePath $logFile -Append
    # ======== THE END ======================
    #Write-Output -InputObject "`n # # # Next: Commit and Sync! # # #`n"
    #    Write-Output -InputObject '' | Tee-Object -FilePath $logFile -Append
} # end function Merge-MyPSFiles

Write-Verbose -Message 'Declaring Function Merge-Modules'
function Merge-Modules {
    # Copy or synchronize latest PowerShell Modules folders between a 'local' and a shared path
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if (-not [bool](Get-Variable -Name DiffSettings -ErrorAction Ignore)) {
        Write-Verbose -Message ('Reading configs from {0}' -f $SettingsFileName)
        Import-MergeSettings
    }

    if (-not $MergeEnvironmentSet) {
        Write-Verbose -Message 'Load custom environmental variables with Get-Environment function'
        Get-Environment
    }

    # Specifying the logFile name now explicitly updates the date stamp on the log file
    $logFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -UFormat '%Y%m%d')))
    Write-Output -InputObject '' | Tee-Object -FilePath $logFile -Append
    Write-Output -InputObject (' # Logging to {0}' -f $logFile)
    Write-Output -InputObject "$(Get-Date -Format g) # Starting Merge-Modules" | Tee-Object -FilePath $logFile -Append

    # EXAMPLE   : PS .\> .\Merge-Module.ps1 -SourcePath .\Modules\ProfilePal -TargetPath ..\GitHub\
    # Technically, per kdiff3 Help, the name of the directory-to-be-merged only needs to be specified once, when the all are the same, just at different root paths.

    $MyModuleNames = $DiffSettings | Select-Object -ExpandProperty RepositorySets | Foreach {$_.Name.split('_')[1]} | Sort-Object -Unique
    Write-Debug -Message ('$MyModuleNames: {0}' -f $MyModuleNames)
    $3PModules = Get-Module -ListAvailable -Refresh | Where-Object -FilterScript {($PSItem.Name -notin $MyModuleNames) -and ($PSItem.Path -notlike '*system32*')} | Select-Object -Unique -Property Name,ModuleBase
    Write-Debug -Message ('$3PModules: {0}' -f $3PModules)

    # *** update design to be considerate of branch bandwidth when copying from local to H:, but optimize for performance when copying in NAS
    if (-not [bool](Get-Variable -Name onServer -Scope Global -ErrorAction Ignore)) {
        $Global:onServer = $false
        if ((Get-WmiObject -Class Win32_OperatingSystem -Property Caption).Caption -like '*Windows Server*') {
            [bool]$Global:onServer = $true
        }
    }
    #Region Merge Modules
        
    # Declare root path of where modules should be merged To
    $ModulesRepo = Join-Path -Path 'R:' -ChildPath 'IT\repo\Modules'

    foreach ($module in $3PModules) {
        # Robocopy /MIR instead of  merge ... no need to merge 3rd party modules
        $rcSource = $module.ModuleBase
        # Exclude updating system managed / SystemDrive  modules
        if ($rcSource -like "$env:SystemDrive*") {
            Write-Verbose -Message ('Skipping System module update: {0}' -f $module.Name) | Tee-Object -FilePath $logFile -Append
        } else {
            $rcTarget = $(join-path -Path $ModulesRepo -ChildPath $module.Name)
            Write-Verbose -Message ('Preparing to merge module: {0}' -f $module.Name) | Tee-Object -FilePath $logFile -Append
            Write-Verbose -Message ('$rcTarget: {0}' -f $rcTarget) | Tee-Object -FilePath $logFile -Append

            Write-Output -InputObject ('Preparing to mirror {0} (from {1} to {2})' -f $module.Name, $rcSource, $rcTarget) | Tee-Object -FilePath $logFile -Append
            
            # To test these paths, we first need to determine if there are spaces in the path string, which need to be escaped
            Write-Debug -Message ('(Test-Path -Path {0})' -f $rcSource)
            Write-Debug -Message $(Test-Path -Path $rcSource)

            Write-Debug -Message ('(Test-Path -Path {0})' -f $rcTarget)
            Write-Debug -Message $(Test-Path -Path $rcTarget)

            #if ((Test-Path -Path $rcSource) -or (Test-Path -Path $rcTarget)) {
            if (Test-Path -Path $rcSource) {
                # robocopy.exe writes wierd characters, if/when we let it share, so robocopy gets it's own log file
                $RCLogFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-robocopy-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -UFormat '%Y%m%d')))
                Write-Verbose -Message ('[Merge-Modules] Update-Repository {0} Source: {1} Destination: {2}' -f $module.Name, $rcSource, $rcTarget) | Tee-Object -FilePath $logFile -Append
                Update-Repository -Name $module.Name -Path $rcSource -Destination $rcTarget

                <# repeat robocopy to PowerShell-Modules repository
                $rcTarget = ('\\hcdata\apps\IT\PowerShell-Modules\{0}' -f $module.Name)
                Write-Verbose -Message ('[Merge-Modules] Updating {0} from {1} to {2}' -f $module.Name, $rcSource, $rcTarget) | Tee-Object -FilePath $logFile -Append
                Update-Repository -Name $module.Name -Path $rcSource -Destination $rcTarget
                #Start-Process -FilePath robocopy.exe -ArgumentList "$rcSource \\hcdata\apps\IT\PowerShell-Modules\$module /MIR /TEE /LOG+:$RCLogFile /R:1 /W:1 /NP /TS /FP /DCOPY:T /DST /XD .git /XF .gitattributes /NJH" -Wait -Verb open
                #>
            } else {
                Write-Warning -Message ('Failed to confirm paths; {0} OR {1}' -f $rcSource, $rcTarget)
            }
        }
    }
    #End Region

  Write-Output -InputObject "`n$(Get-Date -Format g) # Ending Merge-Modules`n" | Tee-Object -FilePath $logFile -Append
  # ======== THE END ======================
} # end function Merge-Modules

Write-Verbose -Message 'Declaring Function Update-Repository'
function Update-Repository {
    <#
        .SYNOPSIS
        Update-Repository provides a command-line wrapper for robocopy.exe, to consistently update (MIRROR) one repository/directory with another

        .DESCRIPTION
        Update-Repository includes argument/parameter checking and logging by default, so the user doesn't have to remember and/or type out numerous robocopy.exe arguments

        .PARAMETER Name
        Specify a friendly Name of the repository being updated

        .PARAMETER Path
        Repository Source Path

        .PARAMETER Destination
        Repository Destination Path, or Target Path

        .EXAMPLE
        Update-Repository -Name MyScripts -Path $env:userprofile\Documents\WindowsPowerShell\Scripts -Destination $env:userprofile\Documents\PowerShell_Scripts.bak
        Effectively backs up MyScripts from their primary/native path to a backup directory
        Thanks to Robocopy, the Path and/or Destination can be UNC paths

    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(Position = 0)]
        [Alias('Label','Repository')]
        [string]
        $Name = 'Repository'
        ,
        [Parameter(Mandatory = $true,HelpMessage='Specify path to the source repository',Position = 1)]
        [ValidateScript({Test-Path -Path $PSItem})]
        [Alias('SourcePath','A','file1')]
        [String]
        $Path
        ,
        [Parameter(Mandatory = $true,HelpMessage='Specify path to the target repository',Position = 2)]
        [ValidateScript({Test-Path -Path $PSItem -IsValid})]
        [Alias('TargetPath','B','file2')]
        [String]
        $Destination
    )
    
    if (-not [bool](Get-Variable -Name DiffSettings -ErrorAction Ignore)) {
        Write-Verbose -Message ('Reading configs from {0}' -f $SettingsFileName)
        Import-MergeSettings
    }

    if (-not [bool](Get-Variable -Name MergeEnvironmentSet -ErrorAction Ignore)) {
        Write-Verbose -Message 'Load custom environmental variables with Get-Environment function'
        Get-Environment
    }

    # Specifying the logFile name now explicitly updates the datestamp on the log file
    $logFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -UFormat '%Y%m%d')))
    Write-Output -InputObject '' | Tee-Object -FilePath $logFile -Append
    Write-Output -InputObject ('logging to {0}' -f $logFile)
    Write-Output -InputObject "$(Get-Date -Format g) # Starting Update-Repository" | Tee-Object -FilePath $logFile -Append
    
    # robocopy.exe writes wierd characters, if/when we let it share, so robocopy gets it's own log file
    $RCLogFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-robocopy-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -UFormat '%Y%m%d')))

    Write-Verbose -Message ('[Update-Repository] Robocopying {0} from {1} to {2}, and logging to {3}' -f $Name, $Path, $Destination, $RCLogFile) | Tee-Object -FilePath $logFile -Append
    Write-Debug -Message ('robocopy.exe "{1}" "{2}" /MIR /TEE /LOG+:"{3}" /IPG:777 /R:1 /W:1 /NP /TS /FP /DCOPY:T /DST /XD .git /XF .gitattributes /NJH' -f $Name, $Path, $Destination, $RCLogFile) #| Tee-Object -FilePath $logFile -Append
    #Start-Process -FilePath "$env:windir\system32\robocopy.exe" -ArgumentList "$Path $Destination /MIR /TEE /LOG+:$RCLogFile /IPG:777 /R:1 /W:1 /NP /TS /FP /DCOPY:T /DST /XD .git /XF .gitattributes /NJH" -Wait -Verb open
    #& $env:windir\system32\robocopy.exe ('"{1}" "{2}" /MIR /TEE /LOG+:"{3}" /IPG:777 /R:1 /W:1 /NP /TS /FP /DCOPY:T /DST /XD .git /XF .gitattributes /NJH' -f $Name, $Path, $Destination, $RCLogFile)

    Start-Process -FilePath "$env:windir\system32\robocopy.exe" -ArgumentList ('"{1}" "{2}" /MIR /TEE /LOG+:"{3}" /IPG:777 /R:1 /W:1 /NP /TS /FP /DCOPY:T /DST /XD .git /XF .gitattributes /NJH' -f $Name, $Path, $Destination, $RCLogFile) -Wait -Verb open

    Write-Output -InputObject "$(Get-Date -Format g) # End of Update-Repository" | Tee-Object -FilePath $logFile -Append
    # Show-Progress -
    # ======== THE END ======================
} # end function Update-Repository