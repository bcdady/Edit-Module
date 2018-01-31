#!/usr/local/bin/powershell
#requires -version 3
[cmdletbinding()]
Param ()

function Get-ModuleMember {
  <#
    .SYNOPSIS
    Examines a specified PowerShell module and returns a custom object displaying all available scripts, functions, and alias the function could export.

    .DESCRIPTION
    Examines a specified PowerShell module manifest, along with all ScriptModule (.psm1) and Script (.ps1) files in the PowerShell module folder, enumerates all function and alias declarations contained within, and returns a custom object designed to make it very easy for updating or creating new PowerShell module manifest files (.psd1)

    .EXAMPLE
    PS .\> Get-ModuleMember -ModuleName EditModule

    ModuleName        : EditModule
    ModulePath        : C:\Users\bdady\Documents\WindowsPowerShell\Modules\EditModule
    ModuleList        :
    RootModule        : EditModule.psm1
    ScriptsToProcess  : @('ModuleMembers.ps1', 'Repair-ModuleManifest.ps1')
    NestedModules     : @('')
    FunctionsToExport : @('Edit-Module', 'Find-Function', 'Format-String', 'Get-ModuleMember', 'Open-AdminISE',
                        'Repair-ModuleManifest')
    AliasesToExport   : @('Open-AdminEditor')

    .EXAMPLE
    PS .\> Get-ModuleMember -ModuleName EditModule -ShowFunctionFile | select -ExpandProperty FunctionFiles
    
    .NOTES
    NAME        :  Get-ModuleMember
    VERSION     :  1.0.0
    LAST UPDATED:  2/16/2016
    AUTHOR      :  Bryan Dady
  #>
  [cmdletbinding(SupportsShouldProcess)]
  Param (
    [Parameter(
        Mandatory,
        Position = 0,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specify a module name (or path to a .psm1 file) to inspect'
    )]
    [ValidateNotNullOrEmpty()]
#    [ValidateScript({$PSItem | ForEach-Object {$PSItem -in (Get-Module -ListAvailable).Name} })] # $PSItem -in (Get-Module -ListAvailable).Name
    [Alias('FilePath','Module','Path')]
    [array]
    $ModuleName,
    [Parameter(Position = 1)]
    [Alias('Resolve')]
    [Switch]
    $ShowFunctionFile
  )

  New-Variable -Name OutputObj -Description 'Object to be returned by this function' -Scope Private

  Write-Verbose -Message ('Test-Path -Path {0}' -f $ModuleName)
  if (Test-Path -Path $ModuleName -ErrorAction Ignore) {
    Write-Verbose -Message 'Test-Path: True'
    if (Test-Path -Path $ModuleName -PathType Leaf -ErrorAction Ignore) {
        $ModuleBase = Split-Path -Path $ModuleName -Resolve
        if (Test-Path -Path $($ModuleName -replace '.psd1','.psm1') -ErrorAction Ignore) {
            $RootModule    = $($ModuleName -replace '.psd1','.psm1')
        } else {
            $RootModule = $ModuleName
        }
    } else {
        $ModuleBase = Resolve-Path -Path $ModuleName
        $RootModule = Join-Path -Path $ModuleBase -ChildPath '*.psm1' -Resolve -ErrorAction Ignore
    }

    $ModuleTitle   = ($ModuleBase -split '\\')[-1]
    $ModuleList    = ''
    $ScriptNames   = ''
    $NestedModules = ''
} else {
    Write-Verbose -Message 'Test-Path: False. Evaluate parameter as an array of Module names, to match against collection of names in Get-Module -ListAvailable'
    Write-Verbose -Message ('$ModuleNameList = Get-Module -Refresh -ListAvailable -All | Select-Object -Property Name -Unique')
    $ModuleNameList = Get-Module -Refresh -ListAvailable -All | Select-Object -Property Name -Unique
      $ModuleName | ForEach-Object {
        Write-Debug -Message ('({0} -in $ModuleNameList)' -f $PSItem, $ModuleNameList)
        if ($PSItem -in $ModuleNameList) {
            $thisModule = Get-Module -Refresh -ListAvailable -Name $PSItem
            Write-Debug -Message ('$thisModule = {0}, {1}' -f $thisModule.Name, $thisModule.Path) -ErrorAction Ignore
            $ModuleTitle    = $($thisModule.Name | Select-Object -Unique)
            $ModuleBase    = $($thisModule.ModuleBase | Select-Object -Unique)
            $RootModule    = $($thisModule.RootModule | Select-Object -Unique)
            $ModuleList    = $($thisModule.ModuleList | Sort-Object | Select-Object -Unique)
            $ScriptNames   = $($thisModule.Scripts | Sort-Object | Select-Object -Unique)
            $NestedModules = $($thisModule.NestedModules | Sort-Object | Select-Object -Unique)
        } else {
            throw 'Invalid Module Name or Path'
        }
    }
}

if (Get-Variable -Name 'ModuleBase' -ErrorAction Ignore) {
    Write-Verbose -Message ('$ModuleBase: {0}' -f $ModuleBase)
} else {
    Write-Warning -Message 'Failed to get variable $ModuleBase'
    throw 'Fatal error getting a handle on the specified Module'
}

  $FunctionFiles = @{}
  $Functions     = @()
  $Aliases       = @()

  $ModuleBase | Get-ChildItem -Recurse -Include *.ps1,*.psm1 | Select-String -pattern '^\s*function (\S+)' | Group-Object -Property Filename | Select-Object -ExpandProperty Group |
  ForEach-Object -Process {
    Write-Debug -Message "Filename: $($PSItem.Filename); Match: $($PSItem.Matches.Groups[1].Value)"
    $FunctionFiles += @{$PSItem.Matches.Groups[1].Value = $(Join-Path -Path $ModuleBase -ChildPath $PSItem.Filename)}
    $Functions += $PSItem.Matches.Groups[1].Value
  } # end foreach Match

  $ModuleBase | Get-ChildItem -Recurse -Include *.ps1,*.psm1 | Select-String -pattern '^(?:[^#\[]{0,7})?(?:New-|Set-)Alias(?:\s*-Name)?\s*?(\S+)' | Group-Object -Property Filename,Matches | Select-Object -ExpandProperty Group |
  ForEach-Object -Process {
    Write-Debug -Message $PSItem
    Write-Debug -Message "Filename: $($PSItem.Filename); Match: $($PSItem.Matches.Groups[1].Value)"
    $Aliases += $PSItem.Matches.Groups[1].Value
  } # end foreach Match

  $ScriptNames = @($ScriptNames -replace $("$($ModuleBase)\" -replace '\\','\\'), '')

  # Optimize New-Object invocation, per Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
  $Private:properties = [ordered]@{
    'ModuleName'        = $ModuleTitle
    'ModulePath'        = $ModuleBase
    'ModuleList'        = $ModuleList
    'RootModule'        = $RootModule
    'ScriptsToProcess'  = "@('" + $($ScriptNames -join "', '") + "')"
    'NestedModules'     = "@('" + $($NestedModules -join "', '") + "')"
    'FunctionsToExport' = "@('" + $(($Functions | Sort-Object | Select-Object -Unique) -join "', '") + "')"
    'AliasesToExport'   = "@('" + $(($Aliases | Sort-Object | Select-Object -Unique) -join "', '") + "')"
  }

  if ($ShowFunctionFile) {
    $Private:properties += @{'FunctionFiles' = $FunctionFiles }
  }
  $Private:RetObject = New-Object -TypeName PSObject -Property $Private:properties
  return $Private:RetObject

} # end function Get-ModuleMember

#    'Functions'     = $($Functions | Sort-Object | Select-Object -Unique)
#    'Aliases'       = $($Aliases | Sort-Object | Select-Object -Unique)
