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
