<#++

Copyright (c) 2011 Microsoft Corporation

Module Name:

    WindowsUpdateProvider.psd1

Abstract:

    This module is the container module definition for the MSFT_WU* CIM
    object CmdLets.

--#>

@{
    GUID = 'faed25e4-6939-439d-8c13-4778ac5ac8a7'
    Author = "Microsoft Corporation"
    CompanyName = "Microsoft Corporation"
    Copyright = "(c) Microsoft Corporation. All rights reserved."
    HelpInfoUri = "https://go.microsoft.com/fwlink/?linkid=390794"
    ModuleVersion = "1.0.0.2"
    PowerShellVersion = '5.1'
    NestedModules = @(
        'MSFT_WUOperations.psm1',
        'MSFT_WUUpdate.cdxml',
        'MSFT_WUSettings.cdxml',
        'MSFT_WUOperations.cdxml'
        )

    TypesToProcess = @('MSFT_WUUpdate.types.ps1xml')

    FormatsToProcess = @('MSFT_WUUpdate.Format.ps1xml')

    FunctionsToExport = @(
        # MSFT_WUSettings.cdxml
        'Get-WUAVersion',
        'Get-WULastInstallationDate',
        'Get-WULastScanSuccessDate',
        'Get-WUIsPendingReboot',
        # MSFT_WUOperations.cdxml
        'Install-WUUpdates'
        # MSFT_WUOperations.psm1
        'Start-WUScan'
        )
    CompatiblePSEditions = @('Desktop','Core')
}
