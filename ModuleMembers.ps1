#requires -version 3
function Get-ModuleMember
{
  [cmdletbinding(SupportsShouldProcess)]
<#
      .SYNOPSIS
      Finds all functions and aliases defined within a function. Intended to make it easier for defining / updating Export-ModuleMember paramters
      .DESCRIPTION
      Uses Get-Module and Select-String to find the functions and aliases defined within the various scripts of a PowerShell Module.
      Returns a custom objects enumerating these functions and aliases, showing a complete Export-ModuleMember statement to be optionally edited, and included at the end of a new or modified .psm1 file
      .EXAMPLE
      PS .\> Get-ModuleMember -ModuleName EditModule

      Modules\EditModule\EditModule.psm1:291:New-Alias -Name Open-AdminEditor -Value Open-AdminISE -ErrorAction Ignore
      Filename: EditModule.psm1; Match: Open-AdminEditor
      Modules\EditModule\ModuleMembers.ps1:42:    $Aliases   = @()
      Filename: ModuleMembers.ps1; Match: es

      ModuleName    : EditModule
      ModulePath    : $env:USERPROFILE\Documents\WindowsPowerShell\Modules\EditModule
      ModuleList    :
      RootModule    : EditModule.psm1
      Scripts       : ModuleMembers.ps1
      NestedModules :
      Functions     : {Edit-Module, Find-Function, Get-ModuleMember, Open-AdminISE}
      Aliases       : {es, Open-AdminEditor}
      FunctionList  : 'Edit-Module', 'Find-Function', 'Get-ModuleMember', 'Open-AdminISE'
      AliasList     : 'es', 'Open-AdminEditor'

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
