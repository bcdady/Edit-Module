#!/usr/local/bin/pwsh
#Requires -Version 3
#========================================
# NAME      : Get-Function.psm1
# LANGUAGE  : Windows PowerShell
# AUTHOR    : Bryan Dady
# UPDATED   : 06/22/2017
# COMMENT   : Locate the script/module file, and/or other helpful details about where an available PowerShell function comes from
#========================================
[CmdletBinding()]
param ()
#Set-StrictMode -Version latest

#Region MyScriptInfo
    Write-Verbose -Message '[Get-Function] Populating $MyScriptInfo'
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
        $CallStack                = Get-PSCallStack | Select-Object -First 1
        # $CallStack | Select Position, ScriptName, Command | format-list # FunctionName, ScriptLineNumber, Arguments, Location
        $Private:MyScriptName     = $CallStack.ScriptName
        $Private:MyCommand        = $CallStack.Command
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
    $Private:MyScriptInfo = New-Object -TypeName PSObject -Property $properties
    Write-Verbose -Message '[Get-Function] $MyScriptInfo populated'
#End Region

Write-Verbose -Message 'Declaring function Get-Function'
function Get-Function {
    [cmdletbinding()]
    Param(
        [Parameter(Position = 0)]
        [string]
        $SearchString = '*'
    )
    Get-ChildItem -Path function: | Where-Object -FilterScript {$_.ModuleName -ne '' -and $_.Name -like "$SearchString"} | Sort-Object -Unique -Property ModuleName, Name
} # end Get-Function

Write-Verbose -Message 'Declaring function Get-FunctionFile'
function Get-FunctionFile {
    <#
        .SYNOPSIS
            Get-FunctionFile returns the parent module of any function matching the specified search parameter 

        .DESCRIPTION
            Get-FunctionFile uses the PowerShell drive of function:\, to return the functions parent module

        .PARAMETER SearchString
            The SearchString parameter specifies the regular expression to match functions with.

        .EXAMPLE
            Get-FunctionFile -SearchString Profile
            Describe what this call does

        .NOTES
            Place additional notes here.

        .LINK
            URLs to related sites
            The first link is opened by Get-Help -Online Get-FunctionFile

        .INPUTS
            List of input types that are accepted by this function.

        .OUTPUTS
            List of output types produced by this function.
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Position = 0)]
        [string]
        $SearchString = '*'
    )
    $Private:FunctionModule = 'No Result'
    $Private:MatchedModules = Get-ChildItem -Path function: | Where-Object -FilterScript {$_.ModuleName -ne '' -and $_.Name -like "$SearchString"} | Sort-Object -Unique -Property ModuleName
    ForEach-Object -InputObject $Private:MatchedModules -Process {
        Get-Module -ListAvailable -Name $_.ModuleName | Where-Object -FilterScript {$_.ModuleType -eq 'Script'} | Sort-Object -Unique | ForEach-Object {
            $ModuleBase = $_.ModuleBase
            $FileList   = $_ | Select-Object -ExpandProperty FileList | ForEach-Object {$_.replace("$ModuleBase\",'')} | Sort-Object -Unique
            $Scripts    = $_ | Select-Object -ExpandProperty Scripts | ForEach-Object {$_.replace("$ModuleBase\",'')} | Sort-Object -Unique
            $Functions  = $_ | Select-Object -ExpandProperty ExportedFunctions | Sort-Object -Unique
        #'Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
            $Private:properties = [ordered]@{
                'Name'          = $_.Name
                'Path'          = $ModuleBase
                'FileList'      = $FileList
                'Scripts'       = $Scripts
                'Definition'    = $_.Definition # aka ScriptBlock
                'Functions'     = $Functions
            }
            $Private:FunctionModule = New-Object -TypeName PSObject -Property $Private:properties
        }
    }
    return $Private:FunctionModule
} # end Get-FunctionFile

Write-Verbose -Message 'Declaring function Find-Function'
Function Find-Function {
    <#
        .SYNOPSIS
            Returns Module details, to which a specified function belongs.
        .DESCRIPTION
            Uses Get-Module and Select-String to find the RootModule which provides a specified ExportedCommand / Function name.
        .EXAMPLE
            PS C:\> Find-Function -SearchPattern 'Edit*'

            ModuleName   : Edit-Module
            FunctionName : EditModule

            ModuleName    FunctionName
            ----------    ------------
            EditModule    {[Edit-Module, Edit-Module], [Open-AdminEditor, Open-AdminEditor], [Find-Function, Find-Function],[Get-ModuleMember, Get-ModuleMembers]...}
            ProfilePal    {[Edit-Profile, Edit-Profile], [Get-Profile, Get-Profile], [Get-UserName, Get-UserName],[Get-WindowTitle, Get-WindowTitle]...}

        .NOTES
            NAME        :  Find-Function
            VERSION     :  1.0.1
            LAST UPDATED:  6/25/2015
            AUTHOR      :  Bryan Dady
            .INPUTS
            None
            .OUTPUTS
            Write-Log
    #>
    Param (
        [Parameter(
            Mandatory,
            HelpMessage='Specify the string to search for matches of.',
            Position = 0
        )]
        [String]
        $SearchPattern,
        # Use SimpleMatch (non RegEx) behavior in Select-String
        [Parameter(Position = 1)]
        [switch]
        $SimpleMatch = $false
    )

    New-Variable -Name OutputObj -Description 'Object to be returned by this function' -Scope Private
    Write-Verbose -Message ('Attempting to match function names with pattern {0} (SimpleMatch: {1})' -f $SearchPattern, $SimpleMatch)
    Get-Module -ListAvailable | Select-Object -Property Name, ExportedCommands | ForEach-Object -Process {
        # find and return only Module/function details where the pattern is matched in the name of the function
        if ($PSItem.ExportedCommands.Keys | Select-String -Pattern $SearchPattern) {
            Write-Verbose -Message ('Matched Function {0} in Module {1}' -f $PSItem.ExportedCommands, $PSItem.Name)
            Write-Debug -Message ('Matched Function {0} in Module {1}' -f $PSItem.ExportedCommands, $PSItem.Name)
            Write-Verbose -Message $PSItem.ExportedCommands
            # Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx
            $Private:properties = @{
                'ModuleName' = $PSItem.Name
                'FunctionName' = $((($PSItem.ExportedCommands | Select-Object -ExpandProperty ExportedCommands).Keys | Select-String -Pattern $SearchPattern) -join ', ')
            }
            $Private:RetObject = New-Object -TypeName PSObject -Property $Private:properties

        return $Private:RetObject
        } # end if
    } # end of Get-Module, ForEach,
} # end function Find-Function

# SIG # Begin signature block
# MIIHqgYJKoZIhvcNAQcCoIIHmzCCB5cCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUglDokcYFgIyT7Ar/SWHkepVr
# DGSgggTFMIIEwTCCA3WgAwIBAgIQKn06fomwQ6RKe8dq7JvZkjBBBgkqhkiG9w0B
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUam6HihyCt8li
# Qw/iuEvbFx94074wDQYJKoZIhvcNAQEBBQAEggEAsbRljmBQAgHeQEGXA8m6dAAL
# 7q2qdRAj9bwjzmmAcNvbMuScFYnnIBqkR4l0Th9oFxnApWWTddeZFm38FNfwJsGL
# Z62sIqGCmtF1VphBQ2O55mRKFUtwxcy4ANPjxJXZCxeMYvluh/bnRLHfNkLhrFKV
# ZEuRKQ+pmts00Edw6DNoZwl2YTUFNETTumHdcJeqbm3LB0sCsL4j7PwD8BK7M5Do
# GaYBzEcdypnj/p7E13UnByP0mjQivd4y7wykUBLhHLHuBNjoFg6uK/A+GQyCyDE2
# Dtx4CgncYqQUkdhBaI7Jjfo8x8GvcrbY5D2K0z2Durh1IVXShCbKTD8diVXpFw==
# SIG # End signature block
