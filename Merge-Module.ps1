#!/usr/local/bin/pwsh
#requires -Version 3
#========================================
# NAME      : Merge-Module.ps1, part of PowerShell Module 'Edit-Module'
# LANGUAGE  : PowerShell
# AUTHOR    : Bryan Dady
# UPDATED   : 02/27/2018
# COMMENT   : PowerShell script to accelerate Repository maintenance / synchronization
# EXAMPLE   : PS .\> .\Merge-Module.ps1 -Path .\Modules\ProfilePal -Destination ..\GitHub\ProfilePal
#========================================
[CmdletBinding(SupportsShouldProcess)]
param ()
#Set-StrictMode -Version latest

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
        Write-Verbose -Message 'MyScriptInfo is:'
        $MyScriptInfo
        Set-Variable -Name IsVerbose -Value $true -Option AllScope
    }
    Write-Verbose -Message '[Merge-Module] $MyScriptInfo populated'
#End Region

# Clean Up this script's Variables. When this script is loaded (dot-sourced), we clean up Merge-Module specific variables to ensure they're current when the next function is invoked
('MergeSettings', 'MergeTool', 'MergeToolArgs', 'MergeEnvironmentSet') | ForEach-Object {
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
New-Variable -Name SettingsFileName -Description 'Path to Merge-Module settings file' -Value 'Merge-Module.json' -Scope Local -Option AllScope -Force
New-Variable -Name MergeSettings -Description ('Settings, from {0}' -f $SettingsFileName) -Scope Global -Option AllScope -Force

$Private:CompareDirectory = Join-Path -Path $(Split-Path -Path $PSCommandPath -Parent) -ChildPath 'Compare-Directory.ps1' -ErrorAction Stop
Write-Verbose -Message (' Dot-Sourcing {0}' -f $Private:CompareDirectory)
. $Private:CompareDirectory

# Get Merge-Module config from Merge-Module.json
Write-Verbose -Message 'Declaring Function Import-MergeSettings'
Function Import-MergeSettings {
  <#
      .SYNOPSIS
      Get user customizable Merge-Module config from .\Merge-Module.json

      .DESCRIPTION
      Import-MergeSettings parses the contents of .\Merge-Module.json, to be referenced by other Merge-Repository.
      Merge-Module.json can be modified to configure a preferred diff/merge tool with it's necesarry parameters, etc.
      It can also hold path definitions of frequent repositories. These path statements can be explicit locaitons or reference environment variables.

      .PARAMETER ShowSettings
      ShowSettings displays the resulting Merge-Module configuration object.
      This can also be achieved with the -Verbose common parameter

      .EXAMPLE
      Import-MergeSettings
      Parses the contents of .\Merge-Module.json to a PowerShell custom object, which is referenced by the Merge-Repository function

      .EXAMPLE
      Import-MergeSettings -ShowSettings
      Parses the contents of .\Merge-Module.json to a PowerShell custom object, and displays the results in the shell
  #>
  [CmdletBinding()]
  param(
    [Parameter(Position = 1)]
    [switch]
    $ShowSettings
  )

  Write-Debug -Message ('$DSPath = Join-Path -Path $(Split-Path -Path {0} -Parent) -ChildPath {1}' -f $PSCommandPath, $SettingsFileName)

  $DSPath = Join-Path -Path $(Split-Path -Path $PSCommandPath -Parent) -ChildPath $SettingsFileName
  Write-Debug -Message ('$MergeSettings = (Get-Content -Path {0} ) -join "`n" | ConvertFrom-Json' -f $DSPath)

  try {
    $MergeSettings = (Get-Content -Path $DSPath) -join "`n" | ConvertFrom-Json -ErrorAction Stop
    Write-Verbose -Message 'Settings imported to $MergeSettings.'
  }
  catch {
    throw ('[Import-MergeSettings]: Critical Error loading settings from from {0}' -f $DSPath)
  }

  if ($MergeSettings) {
    $MergeSettings | Add-Member -NotePropertyName imported -NotePropertyValue (Get-Date -UFormat '%m-%d-%Y') -Force
    $MergeSettings | Add-Member -NotePropertyName SourcePath -NotePropertyValue $DSPath -Force

    if ($IsVerbose -or $ShowSettings) {
      Write-Output -InputObject ' [Verbose] $MergeSettings:' | Out-Host
      Write-Output -InputObject $MergeSettings | Format-List | Out-Host
    }
  }

} # end function Import-MergeSettings

Write-Verbose -Message 'Declaring Function Merge-Repository'
function Merge-Repository {
  [CmdletBinding(SupportsShouldProcess)]
  Param(
    [Parameter(Mandatory,HelpMessage='Specify path to the source repository',Position = 0)]
    [ValidateScript({Test-Path -Path $PSItem})]
    [Alias('SourcePath','A','file1')]
    [String]
    $Path,
    [Parameter(Mandatory,HelpMessage='Specify path to the target repository',Position = 1)]
    [ValidateScript({Test-Path -Path $PSItem -IsValid})]
    [Alias('TargetPath','B','file2')]
    [String]
    $Destination,
    [Parameter(Position = 2)]
    [ValidateScript({Test-Path -Path $PSItem -IsValid})]
    [Alias('MergePath','C')]
    [String]
    $file3 = $null,
    [Parameter(Position = 3)]
    [switch]
    $Recurse = $false,
    [Parameter(Position = 4)]
    [array]
    $Filter = $null
  )
  # ======== SETUP ====================

  $ErrorActionPreference = 'SilentlyContinue'
  if ($MergeSettings -and ($MergeSettings.imported)) {
    Write-Verbose -Message '$MergeSettings instantiated.'
  } else {
    Write-Verbose -Message ('Reading configs from {0} to $MergeSettings' -f $SettingsFileName)
    Import-MergeSettings -ErrorAction Stop
  }

  $ErrorActionPreference = 'Continue'

  if (Get-Variable -Name myPSLogPath -ValueOnly -ErrorAction Ignore) {
    Set-Variable -Name myPSLogPath -Value $HOME
  }

  # Build dynamic logging file path at ...\[My ]Documents\WindowsPowershell\log\[scriptname]-[rundate].log
  $logFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -Format FileDate)))
  Write-Output -InputObject '' | Tee-Object -FilePath $logFile -Append
  Write-Verbose -Message (' # Logging to {0}' -f $logFile)

  $RCLogFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-robocopy-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -Format FileDate)))

  # Resolve path to diff / merge tool
  Write-Verbose -Message ('Getting MergeTool.Path: {0}' -f $MergeSettings.MergeTool.Path)
  $MergeTool = Resolve-Path -Path $ExecutionContext.InvokeCommand.ExpandString($MergeSettings.MergeTool.Path) -ErrorAction SilentlyContinue

  if (Test-Path -Path $MergeTool -PathType Leaf) {
    Write-Verbose -Message ('Using diff tool: {0}' -f $MergeTool)
  } else {
    Write-Warning -Message ('Failed to resolve path to MergeTool (specified in Settings): {0}' -f $MergeTool)
    break
  }

  $MergeOptions = $MergeSettings.MergeTool.Options

  if ($Recurse) {
    $MergeOptions = "/r $MergeOptions"
  }

  # ======== BEGIN ====================
  Write-Verbose -Message ('{0} # Starting Merge-Repository -Path {1} -Destination {2} -file3 {3}' -f (Get-Date -Format g), $Path, $Destination, $file3) | Tee-Object -FilePath $logFile -Append

  Write-Debug -Message ('$MergeOptions: {0}' -f $MergeOptions) | Tee-Object -FilePath $logFile -Append
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
    $null = Test-Path -Path (Resolve-Path -Path $Destination -ErrorAction Ignore)
  }
  catch {
    Write-Warning -Message $PSItem | Tee-Object -FilePath $logFile -Append
    Write-Output -InputObject 'Destination Path not found, so nothing to merge; copying Path contents to Destination.' | Tee-Object -FilePath $logFile -Append
    Copy-Item -Path $Path -Destination $Destination -Recurse -Confirm | Tee-Object -FilePath $logFile -Append
  }

  # To handle spaces in paths, without triggering ValidateScript errors against the functions defined parameters, we copy the function parameters to internal variables
  # file1 / 'A' = $SourcePath ; file2 / 'B' = $TargetPath ; file3 / 'C' = $MergePath
  $SourcePath = (Resolve-Path -Path $Path)
  if (($SourcePath) -and ($SourcePath.ToString().Contains(' '))) {
    Write-Debug -Message 'Wrapping $SourcePath with double-quotes'
    $SourcePath = ('"{0}"' -f $SourcePath.ToString())
  }
  Write-Debug -Message ('Resolved $SourcePath is: {0}' -f $SourcePath)

  $TargetPath = (Resolve-Path -Path $Destination -ErrorAction Ignore)
  if (($TargetPath) -and ($TargetPath.ToString().Contains(' '))) {
    Write-Debug -Message 'Wrapping $TargetPath with double-quotes'
    $TargetPath = ('"{0}"' -f $TargetPath.ToString())
  }
  Write-Debug -Message ('Resolved $TargetPath is: {0}' -f $TargetPath)

  $MergePath = $false
  if ($file3) {
    $MergePath = (Resolve-Path -Path $file3)
    if ($MergePath.ToString().Contains(' ')) {
      Write-Debug -Message 'Wrapping `$MergePath with double-quotes'
      $MergePath = ('"{0}"' -f $MergePath.ToString())
    }
    Write-Debug -Message ('Resolved $MergePath is: {0}' -f $MergePath)
  }

  # ======== PROCESS ==================
  #region Merge
  # Show what we're going to run on the console, then actually run it.
  if ($MergeTool -and $SourcePath -and $TargetPath) {
    if ($MergePath) {
      Write-Verbose -Message ('Detected MergePath : {0}' -f $MergePath)
      Write-Verbose -Message ('{0} {1} {2} --output {3} {4}' -f $MergeTool, $SourcePath, $TargetPath, $MergePath, $MergeOptions)

      if ($PSCmdlet.ShouldProcess($SourcePath,('Merge files with {0}' -f $MergeTool))) {
        Write-Debug -Message ('[DEBUG] {0} -ArgumentList {1} {2} --output {3} {4}' -f $MergeTool, $SourcePath, $TargetPath, $MergePath, $MergeOptions)
        Write-Output -InputObject "Merging $SourcePath `n: $TargetPath -> $MergePath" | Out-File -FilePath $logFile -Append
        Start-Process -FilePath $MergeTool -ArgumentList "$SourcePath $TargetPath $MergePath --output $MergePath $MergeOptions" -Wait | Tee-Object -FilePath $logFile -Append
      }

      # In a 3-way merge, kdiff3 only sync's with merged output file. So, after the merge is complete, we copy the final / merged output to the TargetPath directory.
      # Copy-Item considers double-quotes 'Illegal characters in path',  so we use the original $Destination, instead of $TargetPath
      Write-Verbose -Message ('Copy-Item -Path {0} -Destination {1} -Recurse -Confirm' -f $MergePath, (Split-Path -Path $Destination))
      Copy-Item -Path $MergePath -Destination $(Split-Path -Path $Destination) -Recurse -Confirm

      if ($PSCmdlet.ShouldProcess($MergePath,'Update via Robocopy')) {
        Write-Output -InputObject ('[Merge-Repository] Update {0} back to {1} (using Robocopy)' -f $MergePath, (Split-Path -Path $Destination)) | Tee-Object -FilePath $logFile -Append
        if ($null = Test-Path -Path $Destination -PathType Leaf) {
          $rcTarget = $(Split-Path -Path $Destination)
        } else {
          $rcTarget = $TargetPath
        }
        Write-Output -InputObject ('[Merge-Repository] Updating container from {1} to {2}' -f $MergePath, $rcTarget) | Tee-Object -FilePath $logFile -Append
        Update-Repository -Path $MergePath -Destination $rcTarget -Confirm
      }
    } else {
      Write-Verbose -Message 'No MergePath; 2-way merge'
      Write-Verbose -Message "$MergeTool $SourcePath $TargetPath $MergeOptions"
      if ($PSCmdlet.ShouldProcess($SourcePath,('Merge files with {0}' -f $MergeTool))) {
        Write-Output -InputObject "Merging $SourcePath <-> $TargetPath" | Out-File -FilePath $logFile -Append
        Start-Process -FilePath $MergeTool -ArgumentList "$MergeOptions $SourcePath $TargetPath" -Wait
      }
    }
  } else {
    throw 'No $MergeTool -or $SourcePath -or $TargetPath'
  }
  #EndRegion

  Write-Output -InputObject ''
  Write-Output -InputObject (' {0} # Ending Merge-Repository' -f (Get-Date -Format g)) | Tee-Object -FilePath $logFile -Append
  Write-Output -InputObject ''
  # ======== THE END ======================
} # end function Merge-Repository

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
    [Parameter(Mandatory,HelpMessage='Specify path to the source repository',Position = 1)]
    [ValidateScript({Test-Path -Path $PSItem})]
    [Alias('SourcePath','A','file1')]
    [String]
    $Path
    ,
    [Parameter(Mandatory,HelpMessage='Specify path to the target repository',Position = 2)]
    [ValidateScript({Test-Path -Path $PSItem -IsValid})]
    [Alias('TargetPath','B','file2')]
    [String]
    $Destination
  )

  if (-not [bool](Get-Variable -Name MergeSettings -ErrorAction Ignore)) {
    Write-Verbose -Message ('Reading configs from {0}' -f $SettingsFileName)
    Import-MergeSettings
  }

  # Specifying the logFile name now explicitly updates the datestamp on the log file
  $logFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -Format FileDate)))
  Write-Output -InputObject '' | Tee-Object -FilePath $logFile -Append
  Write-Output -InputObject ('logging to {0}' -f $logFile)
  Write-Output -InputObject "$(Get-Date -Format g) # Starting Update-Repository" | Tee-Object -FilePath $logFile -Append

  # robocopy.exe writes wierd characters, if/when we let it share, so robocopy gets it's own log file
  $RCLogFile = $(Join-Path -Path $myPSLogPath -ChildPath ('{0}-robocopy-{1}.log' -f $($MyScriptInfo.CommandName.Split('.'))[0], (Get-Date -Format FileDate)))

  Write-Verbose -Message ('[Update-Repository] Robocopying {0} from {1} to {2}, and logging to {3}' -f $Name, $Path, $Destination, $RCLogFile) | Tee-Object -FilePath $logFile -Append
  Write-Debug -Message ('robocopy.exe "{1}" "{2}" /MIR /TEE /LOG+:"{3}" /IPG:777 /R:1 /W:1 /NP /TS /FP /DCOPY:T /DST /XD .git /XF .gitattributes /NJH' -f $Name, $Path, $Destination, $RCLogFile) #| Tee-Object -FilePath $logFile -Append

  Start-Process -FilePath "$env:windir\system32\robocopy.exe" -ArgumentList ('"{1}" "{2}" /MIR /TEE /LOG+:"{3}" /IPG:777 /R:1 /W:1 /NP /TS /FP /DCOPY:T /DST /XD .git /XF .gitattributes /NJH' -f $Name, $Path, $Destination, $RCLogFile) -Wait -Verb open

  Write-Output -InputObject "$(Get-Date -Format g) # End of Update-Repository" | Tee-Object -FilePath $logFile -Append

  # ======== THE END ======================
} # end function Update-Repository