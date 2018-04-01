# CONTENTS

<!-- TOC -->

- [Functions](#functions)
  - [Edit-Module](#edit-module-1)
  - [Find-Function](#find-function)
  - [Get-ModuleMember](#get-modulemember)
  - [Open-AdminEditor](#open-admineditor)
- [Repair-ModuleManifest](#repair-modulemanifest)
- [Format-Path](#format-path)
- [NOTES](#notes)

<!-- /TOC -->

## Functions

### Edit-Module

Opens select, or all, files in a PowerShell module, in the ISE, from the console prompt

SYNOPSIS

Opens a specified PowerShell module, for editing, in the ISE

DESCRIPTION

This function uses the Get-Module cmdlet to search for and retrieve information about a module (expected / available in $env:PSModulePath ) and then open specified module member files for editing.

Wildcard characters that resolve to a single module are supported. This function always opens the manifest file to be edited, and prompts/encourages the user/editor to update the ModuleVersion. Additional Module files such as the RootModule / module script (.psm1), and scripts processed by the module can be opened by specifying via the FileType parameter.

PowerShell Module properties changed in PowerShell v3, and so the behavior of the original Edit-Module function (from Scripting Guy Ed Wilson's 'PowerShellISEModule') also changed. The following updates are intended to enable easy editing of both the Data (Manifest) file as well extending similar ease of use for editing the Module script (.psm1), and other scripts included in a Module.

If the Module is installed into a shared file system path (e.g. $env:ProgramFiles), Edit-Module will attempt to open the ISE with elevated permissions, which are necessary to edit a Module in a shared directory. If the user/editor cannot gain elevated permissions, then the ISE will open the module file(s) with read-only rights.

----- EXAMPLE 1 -----

```powershell
Edit-Module -Name EditModule
```

Edit-Module opens the EditModule module's manifest (.psd1) and script module file (.psm1) into a new tab in the ISE for editing

----- EXAMPLE 2 -----

```powershell
Edit-Module Profile*
```

Edit-Module opens any Profile* Module into a new tab in the ISE for editing, using wild card matching for the module name

PARAMETERS

-ModuleName

The name of the module. Wild cards that resolve to a single module are supported.

-FileType

Specifies what module components / files to open for editing. Valid options include: Manifest (.psd1), ScriptModule (.psm1), Scripts (as defined in the ScriptsToProcess property of the module, All.
The default FileType is ScriptModule, which is opened, in addition to the Manifest. Opening the manifest file encourages good practice of updating Version and other attributes.

#### Find-Function

SYNOPSIS

Returns Module details, to which a specified function belongs.

DESCRIPTION

This can also be achieved using Get-ChildItem -Path Function: , but Find-Function prioritizes returning matching functions in the context of the module they are defined in. This is intended to make locating and opening the related module files most efficient.

----- EXAMPLE 1 -----

```powershell
PS .\> Find-Function -SearchPattern 'Get-Profile'

ModuleName FunctionName
---------- ------------
ProfilePal {[Edit-Profile], [Get-Profile], [Get-UserName, Get-UserName], [Get-WindowTitle, Get-WindowTitle]...}
```

#### Get-ModuleMember

SYNOPSIS

Examines a specified PowerShell module and returns a custom object displaying all available scripts, functions, and alias the function could export.

DESCRIPTION

Examines a specified PowerShell module manifest, along with all ScriptModule (.psm1) and Script (.ps1) files in the PowerShell module folder, enumerates all function and alias declarations contained within, and returns a custom object designed to make it very easy for updating or creating new PowerShell module manifest files (.psd1)

Returns a custom object enumerating available Scripts, functions and aliases, modeled toward showing the values needed for New-ModuleManifest or Update-ModuleManifest cmdlets.

----- EXAMPLE 1 -----

    Get-ModuleMember -ModuleName EditModule

    ModuleName        : EditModule
    ModulePath        : ...\Documents\WindowsPowerShell\Modules\EditModule
    ModuleList        :
    RootModule        : EditModule.psm1
    ScriptsToProcess  : @('ModuleMembers.ps1', 'Repair-ModuleManifest.ps1')
    NestedModules     : @('')
    FunctionsToExport : @('Edit-Module', 'Find-Function', 'Format-String', 'Get-ModuleMember', 'Open-AdminEditor',
                        'Repair-ModuleManifest')
    AliasesToExport   : @('Open-AdminEditor')

#### Open-AdminEditor

SYNOPSIS

Launch a new PowerShell ISE window, with elevated privileges. This is primarily a supporting function for calling from the Edit-Module function, but is also exported in case others might find it handy.

DESCRIPTION

Simplifies opening a PowerShell ISE editor instance, with Administrative permissions, from the console / keyboard, instead of having to grab the mouse to Right-Click and select 'Run as Administrator'

Launched a new PowerShell ISE window, with Admin privileges.
This is a close cousin to the Open-AdminConsoleFunction, from [ProfilePal](https://github.com/bcdady/ProfilePal "ProfilePal module, on GitHub") module.

Alias: Open-AdminEditor

PARAMETERS

-Path

The path of the file(s) to be edited.

----- EXAMPLE 1 -----

    Open-AdminEditor -Path $PROFILE.AllUsersAllHosts

Opens AllUsersAllHosts profile script, with permissions to write/save edits.

### Repair-ModuleManifest

SYNOPSIS
Replaces module manifest (psd1) file with one generated by New-ModuleManifest

Description
Preserves original properties from source manifest / data file, and passes the properties as variables to New-ModuleManifest

----- EXAMPLE 1 -----

    Repair-ModuleManifest -Path .\Module\Patchy\Patchy.psd1

### Format-Path

SYNOPSIS

Conditionally escapes spaces in file system paths with double-quotes

DESCRIPTION

Detects white space in the string of a file system path, and wraps the string
with double-quotes if necessary

### NOTES

NAME:  Edit-Module

AUTHOR: originally authored "by ed wilson, msft"

Edited by Bryan Dady to extend PowerShell v3 functionality. Enhancements include Param support, a new FileType parameter, support to edit modules imported into the active session as well as from -ListAvailable. Also adds ability to search for a Module by function name, and opening files in an elevated ISE session as necessary.

#### LINK

[http://www.ScriptingGuys.com](http://www.ScriptingGuys.com "ScriptingGuys.com")
