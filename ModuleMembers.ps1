#requires -version 3
function Get-ModuleMember
{
  [cmdletbinding(SupportsShouldProcess)]
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

      .NOTES
      NAME        :  Get-ModuleMember
      VERSION     :  1.0.0
      LAST UPDATED:  2/16/2016
      AUTHOR      :  Bryan Dady
  #>
  Param (
    [Parameter(
        Mandatory,
        Position = 0,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Specify a module (.psm1 file) to inspect'
    )]
    [ValidateScript({$PSItem -in (Get-Module -ListAvailable).Name})]
    [Alias('FilePath','Module','Path')]
    [string]
    $ModuleName
  )

  New-Variable -Name OutputObj -Description 'Object to be returned by this function' -Scope Private
  $thisModule = Get-Module -ListAvailable -Name $ModuleName

  Write-Debug -Message "`$thisModule = $($thisModule.Name), $($thisModule.Path)"

  $Functions = @()
  $Aliases   = @()

  $thisModule.ModuleBase | Get-ChildItem -Recurse -Include *.ps1,*.psm1 | Select-String -pattern '^\s*function (\S+)' | Group-Object -Property Filename | Select-Object -ExpandProperty Group |
  ForEach-Object -Process {
    Write-Debug -Message "Filename: $($PSItem.Filename); Match: $($PSItem.Matches.Groups[1].Value)"
    $Functions += $PSItem.Matches.Groups[1].Value
  } # end foreach Match

  $thisModule.ModuleBase | Get-ChildItem -Recurse -Include *.ps1,*.psm1 | Select-String -pattern '^(?:[^#\[]{0,7})?(?:New-|Set-)Alias(?:\s*-Name)?\s*?(\S+)' | Group-Object -Property Filename,Matches | Select-Object -ExpandProperty Group |
  ForEach-Object -Process {
    Write-Debug -Message $PSItem
    Write-Debug -Message "Filename: $($PSItem.Filename); Match: $($PSItem.Matches.Groups[1].Value)"
    $Aliases += $PSItem.Matches.Groups[1].Value
  } # end foreach Match

     
  $scriptNames = @($thisModule.Scripts -replace $("$($thisModule.ModuleBase)\" -replace '\\','\\') , '')

  # Optimize New-Object invocation, per Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
  $Private:properties = [ordered]@{
    'ModuleName'        = $($thisModule.Name | Select-Object -Unique)
    'ModulePath'        = $($thisModule.ModuleBase | Select-Object -Unique)
    'ModuleList'        = $($thisModule.ModuleList | Sort-Object | Select-Object -Unique)
    'RootModule'        = $($thisModule.RootModule | Select-Object -Unique)
    'ScriptsToProcess'  = "@('" + $(($scriptNames | Sort-Object | Select-Object -Unique) -join "', '") + "')"
    'NestedModules'     = "@('" + $(($thisModule.NestedModules | Sort-Object | Select-Object -Unique) -join "', '") + "')"
    'FunctionsToExport' = "@('" + $(($Functions | Sort-Object | Select-Object -Unique) -join "', '") + "')"
    'AliasesToExport'   = "@('" + $(($Aliases | Sort-Object | Select-Object -Unique) -join "', '") + "')"
  }

  $Private:RetObject = New-Object -TypeName PSObject -Property $properties
  return $RetObject

} # end function Get-ModuleMember

#    'Functions'     = $($Functions | Sort-Object | Select-Object -Unique)
#    'Aliases'       = $($Aliases | Sort-Object | Select-Object -Unique)
