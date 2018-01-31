#Requires -version 3 -Modules PSLogger
[cmdletbinding()]
Param()

# FYI this same function is also globally defined in ProfilePal module
Write-Verbose -Message 'Declaring function Test-LocalAdmin'
Function Test-LocalAdmin {
  <#
    .SYNOPSIS
    Test for, and return boolean result, if current user has Local Administrator permissions

    .DESCRIPTION
    Test-LocalAdmin uses Windows .NET Security Principal API to detect if the current user is a member of the host OS Local Administrator group.
    This helper function can be easily re-used to determine if a cmdlet or function should be invoked with a -RunAs parameter, to request elevated permissions
    from the current user.

    .EXAMPLE
    Test-LocalAdmin
    False

    .INPUTS
    None

    .OUTPUTS
    Boolean
  #>
    Return ([security.principal.WindowsPrincipal] [security.principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
}

Write-Verbose -Message 'Declaring function Edit-Module'
Function Edit-Module {
    <#
        .SYNOPSIS
            Opens a specified PowerShell module, for editing, in a specified editor tool (Default is PowerShell ISE)
        .DESCRIPTION
            This function uses the Get-Module cmdlet to search for and retrieve information about a module (expected / available in $env:PSModulePath ) and then open specified module member files for editing.

            Wildcard characters that resolve to a single module are supported. This function always opens the manifest file to be edited, and prompts/encourages the user/editor to update the ModuleVersion. Additional Module files such as the RootModule / module script (.psm1), and scripts processed by the module can be opened by specifying via the FileType parameter.

            PowerShell Module properties changed in PowerShell v3, and so the behavior of the original Edit-Module function (from Scripting Guy Ed Wilson's 'PowerShellISEModule') also changed. The following updates are intended to enable easy editing of both the Data (Manifest) file as well extending similar ease of use for editing the Module script (.psm1), and other scripts included in a Module.

            If the Module is installed into a shared file system path (e.g. $env:ProgramFiles), Edit-Module will attempt to open the ISE with elevated permissions, which are necessary to edit a Module in a shared directory. If the user/editor cannot gain elevated permissions, then the ISE will open the module file(s) with read-only rights.
        .EXAMPLE
            Edit-Module -Name EditModule
            Edit-Module opens the EditModule module's manifest (.psd1) and script module file (.psm1) into a new tab in the ISE for editing
        .EXAMPLE
            Edit-Module Profile*
            Edit-Module opens any Profile* Module into a new tab in the ISE for editing, using wild card matching for the module name
        .PARAMETER NAME
            The name of the module. Wild cards that resolve to a single module are supported.
        .NOTES
            NAME:  Edit-Module
            AUTHOR: originally authored "by ed wilson, msft"
            Edited by Bryan Dady (@bcdady)to extend PowerShell v3 functionality.
            Enhancements include Param support, a new FileType parameter, support to edit modules imported into the active session as well as from -ListAvailable.
            Also adds ability to search for a Module by function name, and opening files in an elevated ISE session if/as necessary.
            KEYWORDS: Scripting Techniques, Modules

        .LINK
            http://www.ScriptingGuys.com
            PSLogger
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
        [Parameter(
            Mandatory,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify a module to edit'
        )]
        [ValidateScript({$PSItem -in (Get-Module -ListAvailable | Where-Object {($PSItem.ModuleType -eq 'Script') -and ($($PSItem.Version -as [string]) -gt 0.1) -and ($PSItem.Path -NotLike '*system32*')}).Name})]
        [Alias('Name')]
        [string]
        $ModuleName
        ,
        [Parameter(Position = 1)]
        [ValidateSet('Manifest','ScriptModule','Scripts','All')]
        [string]
        $FileType = 'ScriptModule'
    )

    # * RFE * Enhance Name parameter validation to auto-complete available module names; at least for modules in -ListAvailable
    if ([bool](get-command -Name Get-PSEdit)) {
        # Confirm we can reference the powershell editor specified by the Get-PSEdit / Open-PSEdit functions / psedit alias
        Write-Verbose -Message 'Testing availability of PSEdit alias'
        if (Get-Alias -Name psedit -ErrorAction SilentlyContinue) {
            $PSEdit = (Resolve-Path -Path (Get-PSEdit)).Path
            Write-Verbose -Message ('$PSEdit resolved to {0}' -f $PSEdit)
        } else {
            Write-Verbose -Message 'Determining $PSEdit via Assert-PSEdit function'
            $PSEdit = Assert-PSEdit
            Write-Verbose -Message ('$PSEdit is now assigned to {0}' -f $PSEdit)
        }
    } else {
        Write-Verbose -Message "Determining `$PSEdit via Assert-PSEdit function"
        $PSEdit = Assert-PSEdit
        Write-Verbose -Message ('$PSEdit is now assigned to {0}' -f $PSEdit)
    }
  # Access an installed module as an object
  $ModuleObj = Get-Module -ListAvailable -Name $ModuleName | Where-Object {($PSItem.ModuleType -eq 'Script') -and ($($PSItem.Version -as [string]) -gt 0.1) -and ($PSItem.Path -NotLike '*system32*')} | Sort-Object -Unique
  Write-Verbose -Message ('Retrieved Module (Name): {0}' -f $ModuleObj.Name)

    # Test if we've got a valid module object
    if ($ModuleObj.Path -ne $null) {
        Write-Log -Message ('Preparing to edit module {0} in PowerShell ISE' -f $ModuleObj.ModuleBase) -Function EditModule
        # Now that we've got a valid module object to work with, we can pick the files we want to open in ISE
        # Get the Module Type :: "such as a script file or an assembly. This property is introduced in Windows PowerShell 2.0". 
        # https://msdn.microsoft.com/en-us/library/system.management.automation.psmoduleinfo.moduletype(v=vs.85).aspx
        if ($ModuleObj.ModuleType -eq 'Script') {
            # .Path property provides the full path to the .psd1 module manifest file; as "Introduced in Windows PowerShell 3.0". - 
            # https://msdn.microsoft.com/en-us/library/microsoft.powershell.core.activities.testmodulemanifest_properties(v=vs.85).aspx
            [bool]$SharedModule = $false
            if ($($ModuleObj.Path) | Select-String -Pattern $env:ProgramFiles -SimpleMatch) {
                # Path to module is Program Files, so editing the module file(s) requires elevated privileges
                [bool]$SharedModule = $true
            }
        } else {
            Write-Log -Message ('Unexpected ModuleType is {0}' -f $ModuleObj.ModuleType) -Function EditModule -Verbose
            throw ('Unexpected ModuleType is {0}' -f $ModuleObj.ModuleType)
        } # end if ModuleType

        Write-Log -Message ("Loading module's FileType(s): {0} for editing" -f $FileType) -Function EditModule

        # Define variables for the core module files: script data / manifest file (.psd1) script module (.psm1)
        $ModDataFile = Resolve-Path -Path $ModuleObj.Path -ErrorAction Stop
        $ModRootFile = Join-Path -Path $ModuleObj.ModuleBase -ChildPath $ModuleObj.RootModule -Resolve -ErrorAction Stop

        # This function always opens the manifest to be edited, and prompts/encourages the user/editor to update the ModuleVersion.
        Write-Output -InputObject ("Opening Module {0}, version {1}`n`n`tPlease update the Version and Help Comments to reflect any changes made.`n" -f $ModuleObj.Name, $ModuleObj.Version.ToString())
        Start-Sleep -Milliseconds 500

        switch ($FileType) {
            'ScriptModule' {
                Write-Log -Message 'Editing Module Manifest and ScriptModule' -Function EditModule

                # This function always opens the manifest to be edited, and prompts/encourages the user/editor to update the ModuleVersion.
                # Check if we need to elevate permissions
                if ($SharedModule -and (-not (Test-LocalAdmin))) {
                    # Open modules in new ISE editor instance, with elevated permissions
                    Write-Debug -Message ('Open-AdminEditor -Path {0}, {1}' -f $ModDataFile, $ModRootFile)
                    Open-AdminEditor -Path $ModDataFile,$ModRootFile #Format-Path($ModDataFile,$ModRootFile -join ',')
                } else {
                    # Check if we're running within ISE Host, with psISE variable automatically available
                    if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue')) {
                        # Open modules in active ISE editor, with current permissions
                        Write-Debug -Message ('psEdit -filenames {0}, {1}' -f $ModDataFile, $ModRootFile)
                        Open-PSEdit -ArgumentList $ModDataFile,$ModRootFile # -filenames Format-Path($ModDataFile),Format-Path($ModRootFile)
                    } else {
                        # Open modules in new ISE editor instance, from console, with current permissions
                        Write-Debug -Message ('& {0} {1}, {2}' -f $PSEdit, $ModRootFile)
                        Open-PSEdit -ArgumentList $ModDataFile,$ModRootFile # & $PSEdit Format-Path($ModDataFile,$ModRootFile -join ',')
                    }
                }
            } # end ScriptModule case

            'Scripts' {
                Write-Log -Message 'Editing manifest and scripts' -Function EditModule
                # Check if we need to elevate permissions
                if ($SharedModule -and (-not (Test-LocalAdmin))) {
                    # Open modules in new ISE editor instance, with elevated permissions
                    Write-Debug -Message ('Open-AdminEditor -Path {0}' -f $ModDataFile)
                    Open-AdminEditor -Path $ModDataFile # Format-Path($ModDataFile)
                    Start-Sleep -Milliseconds 500

                    $ModuleObj.scripts | ForEach-Object -Process {
                        #Write-Debug -Message "Open-AdminEditor Format-Path($PSItem)"
                        Write-Debug -Message ('Open-AdminEditor -Path {0}' -f $PSItem)
                        Open-AdminEditor -Path $PSItem # Format-Path($PSItem)
                    }
                } else {
                    # Check if we're running within ISE Host, with psISE variable automatically available
                    if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue')) {
                        # Open all module components in active ISE editor, with current permissions
                        Write-Debug -Message ('Open-PSEdit -ArgumentList $ModDataFile: {0}' -f $ModDataFile)
                        Open-PSEdit -ArgumentList $ModDataFile
                        #Write-Debug -Message "psEdit -filenames $ModuleObj.scripts"
                        Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $ModuleObj.scripts)
                        Open-PSEdit -ArgumentList $ModuleObj.scripts # psEdit -filenames $ModuleObj.scripts
                    } else {
                        # Open modules in new ISE editor instance, from console, with current permissions
                        #Write-Debug -Message "& $PSEdit Format-Path($ModRootFile)"
                        Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $ModRootFile)
                        Open-PSEdit -ArgumentList $ModRootFile # & $PSEdit Format-Path($ModRootFile)

                        $ModuleObj.scripts | ForEach-Object -Process {
                            #Write-Debug -Message "& $PSEdit Format-Path($PSItem)"
                            Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $PSItem)
                            Open-PSEdit -ArgumentList $PSItem # & $PSEdit Format-Path($PSItem)
                        }
                    }
                }
            } # end Scripts case

            'All' {
                Write-Log -Message 'Editing all module files.' -Function EditModule
                if ($SharedModule -and (-not (Test-LocalAdmin))) {
                    # Open modules in new ISE editor instance, with elevated permissions
                    #Write-Debug -Message "Open-AdminEditor Format-Path($ModDataFile,$ModRootFile -join ',')"
                    Write-Debug -Message ('Open-AdminEditor -Path {0},{1}' -f $ModDataFile, $ModRootFile)
                    Open-AdminEditor -Path $ModDataFile,$ModRootFile # Format-Path($ModDataFile,$ModRootFile -join ',')
                    Start-Sleep -Milliseconds 500

                    $ModuleObj.NestedModules | ForEach-Object -Process {
                        Write-Debug -Message ('Open-AdminEditor -Path {0}' -f $PSItem)
                        Open-AdminEditor -Path $PSItem # Format-Path($PSItem)
                    }
                    $ModuleObj.scripts | ForEach-Object -Process {
                        Write-Debug -Message ('Open-AdminEditor -Path {0}' -f $PSItem)
                        Open-AdminEditor -Path $PSItem # Format-Path($PSItem)
                    }
                } else {
                    if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue')) {

                        Write-Debug -Message ('Open-PSEdit -ArgumentList {0},{1}' -f $ModDataFile, $ModRootFile)
                        Open-PSEdit -ArgumentList $ModDataFile,$ModRootFile

                        Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $ModuleObj.NestedModules.path)
                        Open-PSEdit -ArgumentList $ModuleObj.NestedModules.Path

                        Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $ModuleObj.scripts)
                        Open-PSEdit -ArgumentList $ModuleObj.scripts # psEdit -filenames $ModuleObj.scripts
                    } else {

                        Write-Debug -Message ('Open-PSEdit -ArgumentList {0},{1}' -f $ModDataFile, $ModRootFile)
                        Open-PSEdit -ArgumentList $ModDataFile,$ModRootFile
                        Start-Sleep -Milliseconds 500
                        $ModuleObj.NestedModules | ForEach-Object -Process {
                            Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $PSItem)
                            Open-PSEdit -ArgumentList $PSItem # & $PSEdit Format-Path($PSItem)
                        }
                        $ModuleObj.scripts | ForEach-Object -Process {
                            Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $PSItem)
                            Open-PSEdit -ArgumentList $PSItem # & $PSEdit Format-Path($PSItem)
                        }
                    }
                }
            } # end All case

            default {
                Write-Log -Message ('Editing Module Manifest: {0}' -f $ModDataFile) -Function EditModule

                # Check if we need to elevate permissions
                if ($SharedModule -and (-not (Test-LocalAdmin))) {
                    # Open modules in new ISE editor instance, with elevated permissions
                    Write-Debug -Message ('Open-AdminEditor -Path {0}' -f $ModDataFile)
                    Open-AdminEditor -Path $ModDataFile
                } else {
                    # Check if we're running within ISE Host, with psISE variable automatically available
                    if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue')) {
                        # Open modules in active ISE editor, with current permissions
                        Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $ModDataFile)
                        Open-PSEdit -ArgumentList $ModDataFile # psEdit -filenames Format-Path($ModDataFile)
                    } else {
                        # Open modules in new ISE editor instance, from console, with current permissions
                        Write-Debug -Message ('Open-PSEdit -ArgumentList {0}' -f $ModDataFile)
                        Open-PSEdit -ArgumentList $ModRootFile # & $PSEdit Format-Path($ModRootFile)
                    }
                }
            } # end default case
        } # end switch block

    } else {
        Write-Log -InputObject 'Failed to locate module RootModule path for editing.' -Function EditModule -Verbose
    } # end if module path found
} #end function Edit-Module

Write-Verbose -Message 'Declaring function Open-AdminEditor'
Function Open-AdminEditor {
    <#
        .SYNOPSIS
            Launch a new PowerShell editor window, with elevated privileges
        .DESCRIPTION
            Simplifies opening a PowerShell editor instance, with Administrative permissions, from the console / keyboard, instead of having to grab the mouse to Right-Click and select 'Run as Administrator'
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify a module name to edit'
        )]
        [ValidateScript({$PSItem -split ',\s*' | ForEach-Object {test-path -Path $PSItem -PathType Leaf}})]
        [Alias('File','FilePath','Module')]
        [string]
        $Path
    )

    if (Test-LocalAdmin) {
        Write-Log -Message ('Confirmed elevated privileges; opening "{0}".' -f $Path) -Function EditModule
        if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue')) {
            Write-Log -Message 'Opening within ISE.' -Function EditModule
            psEdit -filenames $Path
        } else {
            Write-Log -Message ('Opening with {0}.' -f $PSEdit) -Function EditModule
            & $PSEdit $Path
        }
    } else {
        Write-Log -Message ('Attempting to launch {0} with elevated (RunAs) privileges.' -f $Path) -Function EditModule
        Write-Debug -Message ('Start-Process -FilePath {0} -ArgumentList {1} -Verb RunAs -WindowStyle Normal' -f $PSEdit, (Format-Path -Path $Path))
        Start-Process -FilePath $PSEdit -ArgumentList Format-Path -FilePath -Path $Path -Verb RunAs -WindowStyle Normal
    }
}

Write-Verbose -Message 'Declaring function Format-Path'
Function Format-Path {
  <#
      .SYNOPSIS
      Conditionally escapes spaces in file system paths with double-quotes

      .DESCRIPTION
      Detects white space in the string of a file system path, and wraps the string with double-quotes if necesarry

      .PARAMETER Path
      File system Path (string object) to be formatted

      .EXAMPLE
      Format-Path -Path $env:userprofile
      

      .INPUTS
      String

      .OUTPUTS
      String
  #>
    # Conditionally update the specified variable to wrap a string that contains a space with double-quotes
    [cmdletbinding()]
    Param (
      [Parameter(Mandatory=$true,
        HelpMessage='Specify Path String to format (double-quote) if necesarry.'
      )]
      [String]$Path
    )

    [string]$FormattedString = ''
    Write-Debug -Message ('Format-Path -String {0}' -f $Path)
    # first split on comma, to make double-quote wrapping compatible with the -File syntax expected by powershell_ise.exe
    # $Path -split ",\s*" | ForEach-Object {    
    Write-Debug -Message ("`$Path -split ',\s*' : {0}" -f $PSItem)
    
    if ($Path.Contains(' ')) {
    # Write-Debug -Message "Wrapping `$Path token $PSItem with double-quotes" -Debug
        Write-Debug -Message ('Wrapping $Path {0} with double-quotes' -f $Path)
        $FormattedString = """$Path"""
        if ($PSEdit -like '*code*') {
          Write-Debug -Message ('Wrapping $Path {0} with extra double-quotes, to help play nice with {1}' -f $Path, $PSEdit)
          $FormattedString = """""""$Path"""""""
        }
    } else {
        $FormattedString = $Path
    }
    Write-Debug -Message ('$FormattedString is {0}' -f $FormattedString)

    return $FormattedString
}
