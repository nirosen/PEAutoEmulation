#
# Script Module file for provcmdlets module.
#
# Copyright (c) Microsoft Corporation
#

#
# Cmdlet aliases
#

Set-Alias Add-ProvisioningPackage Install-ProvisioningPackage
Set-Alias Remove-ProvisioningPackage Uninstall-ProvisioningPackage
Set-Alias Add-TrustedProvisioningCertificate Install-TrustedProvisioningCertificate
Set-Alias Remove-TrustedProvisioningCertificate Uninstall-TrustedProvisioningCertificate

Export-ModuleMember -Alias * -Function * -Cmdlet *
