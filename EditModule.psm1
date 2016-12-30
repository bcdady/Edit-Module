#Requires -version 3 -Modules PSLogger

# FYI this same function is also globally defined in ProfilePal module
Function Test-LocalAdmin
{
    Return ([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] 'Administrator')
}

Function Edit-Module
{
<#
  .SYNOPSIS
      Opens a specified PowerShell module, for editing, in the ISE
  .DESCRIPTION
      This function uses the Get-Module cmdlet to search for and retrieve information about a module (expected / available in $env:PSModulePath ) and then open specifed module member files for editing.

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
    [ValidateScript({$PSItem -in (Get-Module -ListAvailable).Name})]
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

  # 1st we attempt to access an imported module
  $ModuleObj = (Get-Module -ListAvailable -Name $ModuleName) | Sort-Object -Unique
  Write-Verbose -Message "Retrieved Module (Name): $($ModuleObj.Name)"

  # Test if we've got a valid module object
  if ($ModuleObj.Path -ne $null) 
  {
    Write-Log -Message "Preparing to edit module $($ModuleObj.ModuleBase) in PowerShell ISE" -Function EditModule
    # Now that we've got a valid module object to work with, we can pick the files we want to open in ISE
    # Get the Module Type :: "such as a script file or an assembly. This property is introduced in Windows PowerShell 2.0". 
    # https://msdn.microsoft.com/en-us/library/system.management.automation.psmoduleinfo.moduletype(v=vs.85).aspx
    if ($ModuleObj.ModuleType -eq 'Script')
    {
      # .Path property provides the full path to the .psd1 module manifest file; as "Introduced in Windows PowerShell 3.0". - 
      # https://msdn.microsoft.com/en-us/library/microsoft.powershell.core.activities.testmodulemanifest_properties(v=vs.85).aspx
      [bool]$SharedModule = $false
      if ($($ModuleObj.Path) | Select-String -Pattern $env:ProgramFiles -SimpleMatch)
      {
        # Path to module is Program Files, so editing the module file(s) requires elevated privileges
        [bool]$SharedModule = $true
      }
    }
    else
    {
      Write-Log -Message "Unexpected ModuleType is $($ModuleObj.ModuleType)" -Function EditModule -Verbose
      throw "Unexpected ModuleType is $($ModuleObj.ModuleType)"
    } # end if moduletype

    Write-Log -Message "Loading module's FileType(s): $FileType for editing" -Function EditModule

    # Define variables for the core module files: script data / manifest file (.psd1) script module (.psm1)
    $ModDataFile = Resolve-Path -Path $ModuleObj.Path -ErrorAction Stop
    $ModRootFile = Join-Path -Path $ModuleObj.ModuleBase -ChildPath $ModuleObj.RootModule -Resolve -ErrorAction Stop

    # This function always opens the manifest to be edited, and prompts/encourages the user/editor to update the ModuleVersion.
    Write-Output -InputObject "`nOpening Module $($ModuleObj.Name), version $($ModuleObj.Version.ToString())`n`n`tPlease update the Version and Help Comments to reflect any changes made.`n"
    Start-Sleep -Milliseconds 500

    switch ($FileType) {
      'ScriptModule'
      {
        Write-Log -Message "Editing Module Manifest and ScriptModule" -Function EditModule

        # This function always opens the manifest to be edited, and prompts/encourages the user/editor to update the ModuleVersion.
        # Check if we need to elevate permissions
        if ($SharedModule -and (-not (Test-LocalAdmin))) 
        {
          # Open modules in new ISE editor instance, with elevated permissions
          Write-Debug -Message "Open-AdminISE -File $ModDataFile, $ModRootFile"
          Open-AdminISE -File $(Format-String($ModDataFile,$ModRootFile -join ','))
        }
        else 
        {
          # Check if we're running within ISE Host, with psISE variable automatically available
          if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue'))
          {
            # Open modules in active ISE editor, with current permissions
            Write-Debug -Message "psEdit -filenames $ModDataFile, $ModRootFile"
            psEdit -filenames $(Format-String($ModDataFile)),$(Format-String($ModRootFile))
          }
          else
          {
            # Open modules in new ISE editor instance, from console, with current permissions
            Write-Debug -Message "& powershell_ise.exe -File $ModRootFile, $ModRootFile"
            & powershell_ise.exe -File $(Format-String($ModDataFile,$ModRootFile -join ','))
          }
        }
      } # end ScriptModule case

      'Scripts'
      {
        Write-Log -Message "Editing manifest and scripts" -Function EditModule
        # Check if we need to elevate permissions
        if ($SharedModule -and (-not (Test-LocalAdmin))) 
        {
          # Open modules in new ISE editor instance, with elevated permissions
          Write-Debug -Message "Open-AdminISE -File $ModDataFile"
          Open-AdminISE -File $(Format-String($ModDataFile))
          Start-Sleep -Milliseconds 500

          $ModuleObj.scripts | ForEach-Object -Process {
            Write-Debug -Message "Open-AdminISE -File $(Format-String($PSItem))"
            Open-AdminISE -File $(Format-String($PSItem))
          }
        }
        else
        {
          # Check if we're running within ISE Host, with psISE variable automatically available
          if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue'))
          {
            # Open all module components in active ISE editor, with current permissions
            Write-Debug -Message "psEdit -filenames `$(Format-String($ModDataFile))"
            psEdit -filenames $(Format-String($ModDataFile))
            Write-Debug -Message "psEdit -filenames $ModuleObj.scripts"
            psEdit -filenames $ModuleObj.scripts
          }
          else
          {
            # Open modules in new ISE editor instance, from console, with current permissions
            Write-Debug -Message "& powershell_ise.exe -File `$(Format-String($ModRootFile))"
            & powershell_ise.exe -File $(Format-String($ModRootFile))

            $ModuleObj.scripts | ForEach-Object -Process {
              Write-Debug -Message "& powershell_ise.exe -File `$(Format-String($PSItem))"
              & powershell_ise.exe -File $(Format-String($PSItem))
            }
          }
        }
      } # end Scripts case

      'All'
      {
        Write-Log -Message "Editing all module files." -Function EditModule
        if ($SharedModule -and (-not (Test-LocalAdmin))) 
        {
          # Open modules in new ISE editor instance, with elevated permissions
          Write-Debug -Message "Open-AdminISE -File `$(Format-String($ModDataFile,$ModRootFile -join ','))"
          Open-AdminISE -File $(Format-String($ModDataFile,$ModRootFile -join ','))
          Start-Sleep -Milliseconds 500

          $ModuleObj.NestedModules | ForEach-Object -Process {
            Write-Debug -Message "Open-AdminISE -File `$(Format-String($PSItem))"
            Open-AdminISE -File $(Format-String($PSItem))
          }
          $ModuleObj.scripts | ForEach-Object -Process {
            Write-Debug -Message "Open-AdminISE -File `$(Format-String($PSItem))"
            Open-AdminISE -File $(Format-String($PSItem))
          }
        }
        else
        {
          if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue'))
          {
            Write-Debug -Message "psEdit -filenames `$(Format-String($ModDataFile)), `$(Format-String($ModRootFile))"
            psEdit -filenames $(Format-String($ModDataFile)),$(Format-String($ModRootFile))
            Write-Debug -Message "psEdit -filenames $($ModuleObj.NestedModules.path)"
            psEdit -filenames $($ModuleObj.NestedModules.path)
            Write-Debug -Message "psEdit -filenames $ModuleObj.scripts"
            psEdit -filenames $ModuleObj.scripts
          }
          else
          {
            Write-Debug -Message "& powershell_ise.exe -File `$(Format-String($ModDataFile,$ModRootFile))"
            & powershell_ise.exe -File $(Format-String($ModDataFile,$ModRootFile -join ','))
            Start-Sleep -Milliseconds 500
            $ModuleObj.NestedModules | ForEach-Object -Process {
              Write-Debug -Message "& powershell_ise.exe -File `$(Format-String($PSItem))"
              & powershell_ise.exe -File $(Format-String($PSItem))
            }
            $ModuleObj.scripts | ForEach-Object -Process {
              Write-Debug -Message "& powershell_ise.exe -File `$(Format-String($PSItem))"
              & powershell_ise.exe -File $(Format-String($PSItem))
            }
          }
        }
      } # end All case

      default
      {
        Write-Log -Message "Editing Module Manifest: $ModDataFile" -Function EditModule

        # Check if we need to elevate permissions
        if ($SharedModule -and (-not (Test-LocalAdmin))) 
        {
          # Open modules in new ISE editor instance, with elevated permissions
          Write-Debug -Message "Open-AdminISE -File $ModDataFile"
          Open-AdminISE -File $(Format-String($ModDataFile))
        }
        else 
        {
          # Check if we're running within ISE Host, with psISE variable automatically available
          if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue'))
          {
            # Open modules in active ISE editor, with current permissions
            Write-Debug -Message "psEdit -filenames `$(Format-String($ModDataFile))"
            psEdit -filenames $(Format-String($ModDataFile))
          }
          else
          {
            # Open modules in new ISE editor instance, from console, with current permissions
            Write-Debug -Message "& powershell_ise.exe -File `$(Format-String($ModRootFile))"
            & powershell_ise.exe -File $(Format-String($ModRootFile))
          }
        }
      } # end default case
    } # end switch block

  }
  else
  {
    Write-Log -InputObject 'Failed to locate module RootModule path for editing.' -Function EditModule -Verbose
  } # end if module path found
} #end function Edit-Module

function Open-AdminISE 
{
<#
  .SYNOPSIS
      Launch a new PowerShell ISE window, with elevated privileges
  .DESCRIPTION
      Simplifies opening a PowerShell ISE editor instance, with Administrative permissions, from the console / keyboard, instead of having to grab the mouse to Right-Click and select 'Run as Administrator'
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
    [ValidateScript({$PSItem -split ",\s*" | ForEach-Object {test-path -Path $PSItem -PathType Leaf}})]
    [Alias('File','FilePath','Module')]
    [string]
    $Path
  )

  if (Test-LocalAdmin)
  {
    Write-Log -Message "Confirmed elevated priveleges; opening ""$Path"" in ISE." -Function EditModule
    if ([bool](Get-Variable -Name psISE -ErrorAction 'SilentlyContinue'))
    {
      psEdit -filenames $Path
    }
    else
    {
      & powershell_ise.exe -File $Path
    }
  }
  else
  {
    Write-Log -Message "Attempting to launch $(Format-String($Path)) in ISE, with elevated (RunAs) priveleges." -Function EditModule
    Start-Process -FilePath "$PSHOME\powershell_ise.exe" -ArgumentList "-File $(Format-String($Path))" -Verb RunAs -WindowStyle Normal
  }
}

New-Alias -Name Open-AdminEditor -Value Open-AdminISE -ErrorAction Ignore

function Format-String
{
  # Conditionally update the specifed variable to wrap a string that contains a space with double-quotes
  [cmdletbinding()]
  Param ([String]$string)

  [string]$formattedstring = ''
  Write-Debug -Message "Format-String -String $string"
  # first split on comma, to make double-quote wrapping compatible with the -File syntax expected by powershell_ise.exe
#  $string -split ",\s*" | ForEach-Object {    
#    Write-Debug -Message "`$string -split ',\s*' : $PSItem"
    if ($string.Contains(' '))
    {
#      Write-Debug -Message "Wrapping `$string token $PSItem with double-quotes" -Debug
      Write-Debug -Message "Wrapping `$string $string with double-quotes"
      $formattedstring = """$string"""
#      $formattedstring = $formattedstring, """$PSItem""" -join ',' -replace '","',',' # -replace '^\"*|\"*$','' -split '"+' -join '","'
    }
    else
    {
      $formattedstring = $string
    }
    Write-Debug -Message "`$formattedstring is $formattedstring"
#  }

  return $formattedstring
}
function Find-Function
{
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
      EditModule    {[Edit-Module, Edit-Module], [Open-AdminISE, Open-AdminISE], [Find-Function, Find-Function],[Get-ModuleMember, Get-ModuleMembers]...}
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
  Get-Module -ListAvailable |
  Select-Object -Property Name, ExportedCommands |
  ForEach-Object -Process {
    # find and return only Module/function details where the pattern is matched in the name of the function
    if ($PSItem.ExportedCommands.Keys |
    Select-String -Pattern $SearchPattern)
    {
      # Optimize New-Object invocation, based on Don Jones' recommendation: https://technet.microsoft.com/en-us/magazine/hh750381.aspx

      $Private:properties = @{
        'ModuleName' = $PSItem.Name
        'FunctionName' = $PSItem.ExportedCommands
      }
      $Private:RetObject = New-Object -TypeName PSObject -Property $Private:properties

      return $Private:RetObject
    } # end if
  } # end of foreach
} # end function Find-Function
