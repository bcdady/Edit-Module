#!/usr/local/bin/pwsh
#Requires -Version 2

[CmdletBinding()]
Param()
#Set-StrictMode -Version latest

#Region MyScriptInfo
    Write-Verbose -Message '[Edit-EnvPath] Populating $MyScriptInfo'
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
    	$Private:CallStack = Get-PSCallStack | Select-Object -First 1
        # $CallStack | Select Position, ScriptName, Command | format-list # FunctionName, ScriptLineNumber, Arguments, Location
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
    $Private:MyScriptInfo = New-Object -TypeName PSObject -Property $Private:properties
    Write-Verbose -Message '[Edit-EnvPath] $MyScriptInfo populated'
#End Region

<#
    .SYNOPSIS
    Edit the System PATH statement globally in Windows Powershell with 4 new Advanced functions. Add-EnvPath, Set-EnvPath, Remove-EnvPath, Get-EnvPath - SUPPORTS -whatif parameter
    .DESCRIPTION
    Adds four new Advanced Functions to allow the ability to edit and Manipulate the System PATH ($Env:Path) from Windows Powershell - Must be run as a Local Administrator
    .EXAMPLE
    PS C:\> Get-EnvPathFromRegistry
    Get Current Path
    .EXAMPLE
    PS C:\> Add-EnvPath C:\Foldername
    Add Folder to Path
    .EXAMPLE
    PS C:\> Remove-EnvPath C:\Foldername
    Remove C:\Foldername from the PATH
    .EXAMPLE
    PS C:\> Set-EnvPath C:\Foldernam;C:\AnotherFolder
    Set the current PATH to the above.  WARNING- ERASES ORIGINAL PATH
    .NOTES
    NAME        :  Set-EnvPath
    VERSION     :  1.0
    LAST UPDATED:  2/20/2015
    AUTHOR      :  Sean Kearney
    # Added 'Test-LocalAdmin' function written by Boe Prox to validate is PowerShell prompt is running in Elevated mode
    # Removed lines for correcting path in Add-EnvPath
    # Switched Path search to an Array for "Exact Match" searching
    # 2/20/2015
    .LINK
    https://gallery.technet.microsoft.com/3aa9d51a-44af-4d2a-aa44-6ea541a9f721
    .LINK
    Test-LocalAdmin
    .INPUTS
    None
    .OUTPUTS
    None
#>

Write-Verbose -Message 'Declaring [Global] Function Set-EnvPath'
Function Set-EnvPath {
    [Cmdletbinding(SupportsShouldProcess)]
    param (
        [parameter(Mandatory,
            Position = 0,
            HelpMessage='Provide the explicit, complete, new PATH environment variable value.',
            ValueFromPipeline
        )]
        [Alias('Path','Folder')]
        [String[]]$NewPath
    )

    # Clean up potential garbage in New Path ($AddedFolder)
    $NewPath = $NewPath.replace(';;',';')

    if ( -not (Test-LocalAdmin) ) {
        # Set / override the Environment Path for this session via variable
        if ( $PSCmdlet.ShouldProcess($NewPath) ) {
            $Env:PATH = $NewPath
            # Show what we just did
            Return $NewPath
        }
    } else {
        # Set / override the Environment Path permanently, via registry
        if ( $PSCmdlet.ShouldProcess($NewPath) ) {
            Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $NewPath
            # Show what we just did
            Return $NewPath
        }
    }
}

Write-Verbose -Message 'Declaring [Global] Function Add-EnvPath'
Function Add-EnvPath {
  [Cmdletbinding(SupportsShouldProcess)]
  param (
    [parameter(Mandatory,
        Position = 0,
        HelpMessage='Provide the new path value to add to the PATH environment variable.',
        ValueFromPipeline
    )]
    [Alias('Path','Folder')]
    [String[]]$AddedFolder
  )

  # See if a new Folder has been supplied
  If (-not $AddedFolder) {
    Write-Warning -Message 'No folder specified. $Env:PATH Unchanged'
    Return $False
  }

  # See if the new Folder exists on the File system
  If (-not (Test-Path -Path $AddedFolder -PathType Container)) {
    Write-Warning -Message 'Folder (specified by Parameter) is not a Directory or was not found; Cannot be added to $Env:PATH'
    Return $False
  }

  If (Test-LocalAdmin) {
    # Get the Current Search Path from the Environment keys in the Registry
    # Make this more REG_EXPAND_SZ friendly -- see https://www.sepago.com/blog/2013/08/22/reading-and-writing-regexpandsz-data-with-powershell
    $OldPath = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('System\CurrentControlSet\Control\Session Manager\Environment').GetValue('PATH',$False, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  } else {
    # Get the Environment Path for this session via variable
    $OldPath = $Env:PATH
  }

  # Clean up duplicates and potential garbage from 'Old' Path
  $OldPath = $OldPath.replace(';;',';')
  $OldPath = ($OldPath -Split ';' | Sort-Object -Unique) -join ';'

  # See if the new Folder is already IN the Path
  $PathAsArray = ($Env:PATH).split(';')
  If ($PathAsArray -contains $AddedFolder -or $PathAsArray -contains $AddedFolder+'\') {
    Write-Verbose -Message 'Folder already within $Env:PATH'
    Return $False
  }

  # Clean up potential garbage in New Path ($AddedFolder)
  $AddedFolder = $AddedFolder.replace(';;',';')
  $AddedFolder = Resolve-Path -Path $AddedFolder

  # Set the New Path
  $NewPath = ('{0};{1}' -f $OldPath, $AddedFolder)
  If (Test-LocalAdmin) {
    if ( $PSCmdlet.ShouldProcess($AddedFolder) ) {
      Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $NewPath
      # Show our results back to the world
      Return $NewPath
    }
  } else {
    # Set / override the Environment Path for this session via variable
    if ( $PSCmdlet.ShouldProcess($NewPath) ) {
      $Env:PATH = $NewPath
      # Show what we just did
      Return $NewPath
    }
  }
}

Write-Verbose -Message 'Declaring [Global] Function Repair-EnvPath'
Function Repair-EnvPath {
    # Split Path into a unique member array for processing
    $NewPath = $Env:Path.Split(';') | Sort-Object -Unique

    # Replace explicit paths with their Windows expandable variable, and store in a new variable
    #$NewPath = $NewPath -replace '\w:\\Program Files \(x86\)','%ProgramFiles(x86)%'
    #$NewPath = $NewPath -replace '\w:\\Program Files','%ProgramFiles%'
    #$NewPath = $NewPath -replace '\w:\\ProgramData','%ProgramData%'
    #$NewPath = $NewPath -replace '\w:\\Windows','%SystemRoot%'

    # Remove any trailing \
    $NewPath = $NewPath -replace '(.+)\\$','$1'

    # Double-check all entries are unique
    $NewPath = $NewPath | Sort-Object -Unique

    # Restore semicolon delimited format
    $NewPath = $NewPath -join ';'

    # Make it so
    Set-EnvPath -Path $NewPath
}

Write-Verbose -Message 'Declaring [Global] Function Get-EnvPath'
Function Get-EnvPath {
    Return $Env:Path
}

Write-Verbose -Message 'Declaring [Global] Function Get-EnvPathFromRegistry'
Function Get-EnvPathFromRegistry {
    Return (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
}

Write-Verbose -Message 'Declaring [Global] Function Test-EnvPath'
Function Test-EnvPath {
  [Cmdletbinding()]
  param (
    [parameter(Mandatory,
        Position = 0,
        HelpMessage='Provide the path value to Test if it is found in the PATH environment variable.',
        ValueFromPipeline
    )]
    [Alias('SearchString','String')]
    [String]$Folder
    ,
    [parameter(
        Position = 1
    )]
    [Alias('Source')]
    [Switch]$FromRegistry = $False
  )

  if ($FromRegistry) {
    $VarPath = Get-EnvPathFromRegistry
  } else {
    $VarPath = Get-EnvPath
  }
  # Split Path into a unique member array for processing
  $PathArray = $VarPath.Split(';') | Sort-Object -Unique
  if ($PathArray -like $Folder) {
    Write-Verbose -Message ($PathArray -like $Folder)
    $Result = $True
  } else {
    $Result = $False
  }

  Return $Result
}

Write-Verbose -Message 'Declaring [Global] Function Remove-EnvPath'
Function Remove-EnvPath {
  [Cmdletbinding(SupportsShouldProcess)]
  param (
    [parameter(Mandatory,
        Position = 0,
        HelpMessage='Provide the path value to remove from the PATH environment variable.',
        ValueFromPipeline
    )]
    [Alias('Path','Folder')]
    [String[]]$RemovedFolder
  )

  If (-not (Test-LocalAdmin)) {
    Write-Warning -Message 'Required Administrator permissions not available.'
    Return $False
  }

  # Get the Current Search Path from the Environment keys in the Registry
  $OldPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path

  # Verify item exists as an EXACT match before removing
  If ($Oldpath.split(';') -contains $RemovedFolder) {
    # Find the value to remove, replace it with $NULL.  If it's not found, nothing will change
    $NewPath = $OldPath.replace($RemovedFolder,$NULL)
  }

  # Clean up any potential garbage from Path
  $Newpath = $NewPath.replace(';;',';')

  # Update the Environment Path
  if ( $PSCmdlet.ShouldProcess($RemovedFolder) ) {
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $NewPath

    # Show what we just did
    Return $NewPath
  }
}
