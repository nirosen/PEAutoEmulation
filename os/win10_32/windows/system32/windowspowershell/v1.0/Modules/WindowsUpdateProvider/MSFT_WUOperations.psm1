# This function's purpose is to take the output of the MI provider, an array of fixed size, and convert it to an array list of non-fixed size.
# The reason for this is so that a caller of this module is able to easily select which updates they wish to download & install
function Start-WUScan
{
    param
    (
        [parameter(Mandatory = $false)]
        $SearchCriteria
    )

    If($SearchCriteria -eq $null)
    {
        $scanres = Invoke-CimMethod -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperations -MethodName ScanForUpdates
    }
    else
    {
        $scanres = Invoke-CimMethod -Namespace root/Microsoft/Windows/WindowsUpdate -ClassName MSFT_WUOperations -MethodName ScanForUpdates -Arguments @{SearchCriteria=$SearchCriteria}
    }
    
    if($scanres.ReturnValue -eq 0)
    {
        $arrlist = New-Object System.Collections.ArrayList
        $arrlist.AddRange($scanres.Updates) | out-null

        # Comma is added to prevent powershell from converting return to an array
        return ,$arrlist
    }
    else
    {
        Write-Error "Scan hit error: $scanres.ReturnValue"
    }
}