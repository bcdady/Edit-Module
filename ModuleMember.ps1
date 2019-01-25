#!/usr/local/bin/pwsh
#requires -version 3
[cmdletbinding()]
Param ()

Write-Verbose -Message 'Declaring Function Get-ModuleMember'
function Get-ModuleMember {
  <#
      .SYNOPSIS
      Examines a specified PowerShell module and returns a custom object displaying all available scripts, functions, and alias the function could export.

      .DESCRIPTION
      Examines a specified PowerShell module manifest, along with all ScriptModule (.psm1) and Script (.ps1) files in the PowerShell module folder, enumerates all function and alias declarations contained within, and returns a custom object designed to make it very easy for updating or creating new PowerShell module manifest files (.psd1)

      .EXAMPLE
      PS .\> Get-ModuleMember -ModuleName Edit-Module

      ModuleName        : Edit-Module
      ModulePath        : C:\Users\bdady\Documents\WindowsPowerShell\Modules\Edit-Module
      ModuleList        :
      RootModule        : Edit-Module.psm1
      ScriptsToProcess  : @('ModuleMembers.ps1', 'Repair-ModuleManifest.ps1')
      NestedModules     : @('')
      FunctionsToExport : @('Edit-Module', 'Find-Function', 'Format-String', 'Get-ModuleMember', 'Open-AdminISE',
      'Repair-ModuleManifest')
      AliasesToExport   : @('Open-AdminEditor')

      .EXAMPLE
      PS .\> Get-ModuleMember -ModuleName Edit-Module -ShowFunctionFile | select -ExpandProperty FunctionFiles
    
      .NOTES
      NAME        :  Get-ModuleMember
      VERSION     :  1.0.0
      LAST UPDATED:  2/16/2016
      AUTHOR      :  Bryan Dady
  #>
  [cmdletbinding(SupportsShouldProcess)]
  Param (
    [Parameter(
        Position = 0,
        Mandatory,
        ValueFromPipeline,
        ValueFromPipelineByPropertyName,
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
      if (Test-Path -Path $($ModuleName -replace '.psd1', '.psm1') -ErrorAction Ignore) {
        $RootModule    = $($ModuleName -replace '.psd1', '.psm1')
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
    #Write-Verbose -Message ('$ModuleNameList = Get-Module -Refresh -ListAvailable -All | Select-Object -Property Name -Unique')
    #$ModuleNameList = Get-Module -Refresh -ListAvailable -All -Name $ModuleName | Select-Object -Property Name -Unique
    #$ModuleNameList | ForEach-Object -Process {
    #    Write-Debug -Message ('({0} -in $ModuleNameList)' -f $PSItem, $ModuleNameList)
    #    if ($PSItem.Name -in $ModuleNameList) {
    #        Write-Verbose -Message 'Confirmed Module Name, Path'
            $thisModule = Get-Module -Refresh -ListAvailable -Name $ModuleName #$PSItem
            Write-Debug -Message ('$thisModule = {0}, {1}' -f $thisModule.Name, $thisModule.Path) -ErrorAction Ignore
            $ModuleTitle   = $($thisModule.Name | Select-Object -Unique)
            $ModuleBase    = $($thisModule.ModuleBase | Select-Object -Unique)
            $RootModule    = $($thisModule.RootModule | Select-Object -Unique)
            $ModuleList    = $($thisModule.ModuleList | Sort-Object | Select-Object -Unique)
            $ScriptNames   = $($thisModule.Scripts | Sort-Object | Select-Object -Unique)
            $NestedModules = $($thisModule.NestedModules | Sort-Object | Select-Object -Unique)
        # } else {
        #     Write-Warning -Message 'Invalid Module Name or Path'
        # }
    #}
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

  $ModuleBase | Get-ChildItem -Recurse -Include *.ps1, *.psm1 | Select-String -Pattern '^\s*function (\S+)' | `
    Group-Object -Property Filename |
    Select-Object -ExpandProperty Group | ForEach-Object -Process {
        Write-Debug -Message ('Filename: {0}; Match: {1}' -f $PSItem.Filename, $PSItem.Matches.Groups[1].Value)
        $FunctionFiles += @{ $PSItem.Matches.Groups[1].Value = $(Join-Path -Path $ModuleBase -ChildPath $PSItem.Filename) }
        $Functions += $PSItem.Matches.Groups[1].Value
    } # end foreach Match

  $ModuleBase | Get-ChildItem -Recurse -Include *.ps1, *.psm1 | Select-String -Pattern '^(?:[^#\[]{0,7})?(?:New-|Set-)Alias(?:\s*-Name)?\s*?(\S+)' | `
    Group-Object -Property Filename, Matches | Select-Object -ExpandProperty Group | ForEach-Object -Process {
        Write-Debug -Message $PSItem
        Write-Debug -Message ('Filename: {0}; Match: {1}' -f $PSItem.Filename, $PSItem.Matches.Groups[1].Value)
        $Aliases += $PSItem.Matches.Groups[1].Value
    } # end foreach Match

  $ScriptNames = @($ScriptNames -replace $(('{0}\' -f ($ModuleBase)) -replace '\\', '\\'), '')

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
    $Private:properties += @{
      'FunctionFiles' = $FunctionFiles
    }
  }
  $Private:RetObject = New-Object -TypeName PSObject -Property $Private:properties
  return $Private:RetObject
} # end function Get-ModuleMember

# SIG # Begin signature block
# MIIHqgYJKoZIhvcNAQcCoIIHmzCCB5cCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWyTemLlOnGHbV1hF/OenSgMF
# QlOgggTFMIIEwTCCA3WgAwIBAgIQKn06fomwQ6RKe8dq7JvZkjBBBgkqhkiG9w0B
# AQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQC
# AQUAogMCASAwgZgxCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdNb250YW5hMREwDwYD
# VQQHDAhNaXNzb3VsYTETMBEGA1UECgwKQnJ5YW4gRGFkeTEVMBMGA1UECwwMQ29k
# ZSBTaWduaW5nMRowGAYDVQQDDBFTZWN1cmUgUG93ZXJTaGVsbDEcMBoGCSqGSIb3
# DQEJARYNYnJ5YW5AZGFkeS51czAeFw0xODEyMzAwMzM5NDNaFw0xOTEyMzAwMzU5
# NDNaMIGYMQswCQYDVQQGEwJVUzEQMA4GA1UECAwHTW9udGFuYTERMA8GA1UEBwwI
# TWlzc291bGExEzARBgNVBAoMCkJyeWFuIERhZHkxFTATBgNVBAsMDENvZGUgU2ln
# bmluZzEaMBgGA1UEAwwRU2VjdXJlIFBvd2VyU2hlbGwxHDAaBgkqhkiG9w0BCQEW
# DWJyeWFuQGRhZHkudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3
# tawJQoBbR3HJe+GYdZMLf0jhbO7FM0SoX8509y1RR62TTFsgnK2Aqa1SbzTysBMS
# rL0+MI6ud44lC7/qCSTcCoqIpSMGtJ56QxJ3lLcRBe5Xb4xDLvzitpaGeKlugHfd
# QAAd1w0SetXT3D/AjnzW0/WrYZ6in3I9FzFF+JC24t4PGyQUaeE6UgCtEVyOdRGA
# gRr1Xhz9jomUVw84qof4LAAdfroR1z7VgY8j2Mq66HzsY63/y9iiBJSOeQ+OvBuz
# 6aaBoiiOflQ0HxbZYXuj5HSWeRPaFa/cM2Vp1iBJQ0K0ptaS6pAx2yOngWKhTGUY
# OPaFRxELdUICyBrSWFdlAgMBAAGjgZwwgZkwDgYDVR0PAQH/BAQDAgeAMFMGA1Ud
# EQRMMEqgHQYKKwYBBAGCNxQCA6APDA1icnlhbkBkYWR5LnVzgQ1icnlhbkBkYWR5
# LnVzggt3d3cuZGFkeS51c4INYnJ5YW4uZGFkeS51czATBgNVHSUEDDAKBggrBgEF
# BQcDAzAdBgNVHQ4EFgQUZUQGb3yr7zNZSgdlXQEmJ9SpdjIwQQYJKoZIhvcNAQEK
# MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
# AKIDAgEgA4IBAQCe91LHEw1CznKDFzRP4zzRf8DL/ffFgkOPjnb3e1JYiuTTobii
# HQtrTBRxnRh3t5nYQOkAdQZRW/VY2cUopMnVvBo1iJKkosPyVvP+QeZ/V9J9kJR0
# cYUpiMXmFKB6JMfGCfHG+cN3t57HDC2+yXD/tkvF0DwKrIXVz6MJIAq6ww9ZLs+d
# 7dUYo1T4I8F3J28X5YBiBPTQ0W2or2CWfnTNwxzQavdrRFoPBaZgXTrkdIjCuI9G
# 4Tnl1lNfz5qCshSBhOrwwYUkTuZv32hcYe1Yuj2exBfEF3gT5Cbgrp25v37dRDZ5
# qmIb6V9gpxBxUlJp2ApxyCvvGOejlh6BhtaxMYICTzCCAksCAQEwga0wgZgxCzAJ
# BgNVBAYTAlVTMRAwDgYDVQQIDAdNb250YW5hMREwDwYDVQQHDAhNaXNzb3VsYTET
# MBEGA1UECgwKQnJ5YW4gRGFkeTEVMBMGA1UECwwMQ29kZSBTaWduaW5nMRowGAYD
# VQQDDBFTZWN1cmUgUG93ZXJTaGVsbDEcMBoGCSqGSIb3DQEJARYNYnJ5YW5AZGFk
# eS51cwIQKn06fomwQ6RKe8dq7JvZkjAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUQXUQRlCIpNWG
# 83GXVleofjhUUkswDQYJKoZIhvcNAQEBBQAEggEAngcv8L4SVInNC+ZByam34TkT
# 0nxJ2vqmC3WDzJFZaudtPd4TPB/QO5sYAvW/AEfYOJJrzN0gQOGq2gkf4jfWVuLF
# Xtc87j1rNGJFAntbwwS0r6EhPpWv3LDQCOT0HSItlcVjlFLm0CmYA4/gOSFRUdqU
# 01TBSVVlDCOfJlxukD7yfubbMaZ2wYkANZkbR7lJtdgJ/0k/cDolY0kt2geWZngK
# 3+x/15miJxlSSCYGeRMRwJQrkOU/fxbCVtU7Nixt/UHfABfV9yIcWZqA6fEINWtr
# yc/SpTelpPxuw1tM17muHhAwJ3kGokOJYo+JmngA1UgeMXIfxn+eJfaVJTHb4Q==
# SIG # End signature block
