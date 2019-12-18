'----------------------------------------------------------------------
'
' Copyright (c) Microsoft Corporation. All rights reserved.
'
' Abstract:
' prndrvr.vbs - driver script for WMI on Windows 
'     used to add, delete, and list drivers.
'
' Usage:
' prndrvr [-adlx?] [-m model][-v version][-e environment][-s server]
'         [-u user name][-w password][-h file path][-i inf file]
'
' Example:
' prndrvr -a -m "driver" -v 3 -e "Windows NT x86"
' prndrvr -d -m "driver" -v 3 -e "Windows x64"
' prndrvr -d -m "driver" -v 3 -e "Windows IA64"
' prndrvr -x -s server
' prndrvr -l -s server
'
'----------------------------------------------------------------------

option explicit

'
' Debugging trace flags, to enable debug output trace message
' change gDebugFlag to true.
'
const kDebugTrace = 1
const kDebugError = 2
dim gDebugFlag

gDebugFlag = false

'
' Operation action values.
'
const kActionUnknown    = 0
const kActionAdd        = 1
const kActionDel        = 2
const kActionDelAll     = 3
const kActionList       = 4

const kErrorSuccess     = 0
const kErrorFailure     = 1

const kNameSpace        = "root\cimv2"

'
' Generic strings
'
const L_Empty_Text                 = ""
const L_Space_Text                 = " "
const L_Error_Text                 = "Error"
const L_Success_Text               = "Success"
const L_Failed_Text                = "Failed"
const L_Hex_Text                   = "0x"
const L_Printer_Text               = "Printer"
const L_Operation_Text             = "Operation"
const L_Provider_Text              = "Provider"
const L_Description_Text           = "Description"
const L_Debug_Text                 = "Debug:"

'
' General usage messages
'
const L_Help_Help_General01_Text   = "Usage: prndrvr [-adlx?] [-m model][-v version][-e environment][-s server]"
const L_Help_Help_General02_Text   = "               [-u user name][-w password][-h path][-i inf file]"
const L_Help_Help_General03_Text   = "Arguments:"
const L_Help_Help_General04_Text   = "-a     - add the specified driver"
const L_Help_Help_General05_Text   = "-d     - delete the specified driver"
const L_Help_Help_General06_Text   = "-e     - environment  ""Windows {NT x86 | X64 | IA64}"""
const L_Help_Help_General07_Text   = "-h     - driver file path"
const L_Help_Help_General08_Text   = "-i     - fully qualified inf file name"
const L_Help_Help_General09_Text   = "-l     - list all drivers"
const L_Help_Help_General10_Text   = "-m     - driver model name"
const L_Help_Help_General11_Text   = "-s     - server name"
const L_Help_Help_General12_Text   = "-u     - user name"
const L_Help_Help_General13_Text   = "-v     - version"
const L_Help_Help_General14_Text   = "-w     - password"
const L_Help_Help_General15_Text   = "-x     - delete all drivers that are not in use"
const L_Help_Help_General16_Text   = "-?     - display command usage"
const L_Help_Help_General17_Text   = "Examples:"
const L_Help_Help_General18_Text   = "prndrvr -a -m ""driver"" -v 3 -e ""Windows NT x86"""
const L_Help_Help_General19_Text   = "prndrvr -d -m ""driver"" -v 3 -e ""Windows x64"""
const L_Help_Help_General20_Text   = "prndrvr -a -m ""driver"" -v 3 -e ""Windows IA64"" -i c:\temp\drv\drv.inf -h c:\temp\drv"
const L_Help_Help_General21_Text   = "prndrvr -l -s server"
const L_Help_Help_General22_Text   = "prndrvr -x -s server"
const L_Help_Help_General23_Text   = "Remarks:"
const L_Help_Help_General24_Text   = "The inf file name must be fully qualified. If the inf name is not specified, the script uses"
const L_Help_Help_General25_Text   = "one of the inbox printer inf files in the inf subdirectory of the Windows directory."
const L_Help_Help_General26_Text   = "If the driver path is not specified, the script searches for driver files in the driver.cab file."
const L_Help_Help_General27_Text   = "The -x option deletes all additional printer drivers (drivers installed for use on clients running"
const L_Help_Help_General28_Text   = "alternate versions of Windows), even if the primary driver is in use. If the fax component is installed,"
const L_Help_Help_General29_Text   = "this option deletes any additional fax drivers. The primary fax driver is also deleted if it is not"
const L_Help_Help_General30_Text   = "in use (i.e. if there is no queue using it). If the primary fax driver is deleted, the only way to"
const L_Help_Help_General31_Text   = "re-enable fax is to reinstall the fax component."

'
' Messages to be displayed if the scripting host is not cscript
'
const L_Help_Help_Host01_Text      = "This script should be executed from the Command Prompt using CScript.exe."
const L_Help_Help_Host02_Text      = "For example: CScript script.vbs arguments"
const L_Help_Help_Host03_Text      = ""
const L_Help_Help_Host04_Text      = "To set CScript as the default application to run .VBS files run the following:"
const L_Help_Help_Host05_Text      = "     CScript //H:CScript //S"
const L_Help_Help_Host06_Text      = "You can then run ""script.vbs arguments"" without preceding the script with CScript."

'
' General error messages
'
const L_Text_Error_General01_Text  = "The scripting host could not be determined."
const L_Text_Error_General02_Text  = "Unable to parse command line."
const L_Text_Error_General03_Text  = "Win32 error code"

'
' Miscellaneous messages
'
const L_Text_Msg_General01_Text    = "Added printer driver"
const L_Text_Msg_General02_Text    = "Unable to add printer driver"
const L_Text_Msg_General03_Text    = "Unable to delete printer driver"
const L_Text_Msg_General04_Text    = "Deleted printer driver"
const L_Text_Msg_General05_Text    = "Unable to enumerate printer drivers"
const L_Text_Msg_General06_Text    = "Number of printer drivers enumerated"
const L_Text_Msg_General07_Text    = "Number of printer drivers deleted"
const L_Text_Msg_General08_Text    = "Attempting to delete printer driver"
const L_Text_Msg_General09_Text    = "Unable to list dependent files"
const L_Text_Msg_General10_Text    = "Unable to get SWbemLocator object"
const L_Text_Msg_General11_Text    = "Unable to connect to WMI service"


'
' Printer driver properties
'
const L_Text_Msg_Driver01_Text     = "Server name"
const L_Text_Msg_Driver02_Text     = "Driver name"
const L_Text_Msg_Driver03_Text     = "Version"
const L_Text_Msg_Driver04_Text     = "Environment"
const L_Text_Msg_Driver05_Text     = "Monitor name"
const L_Text_Msg_Driver06_Text     = "Driver path"
const L_Text_Msg_Driver07_Text     = "Data file"
const L_Text_Msg_Driver08_Text     = "Config file"
const L_Text_Msg_Driver09_Text     = "Help file"
const L_Text_Msg_Driver10_Text     = "Dependent files"

'
' Debug messages
'
const L_Text_Dbg_Msg01_Text        = "In function AddDriver"
const L_Text_Dbg_Msg02_Text        = "In function DelDriver"
const L_Text_Dbg_Msg03_Text        = "In function DelAllDrivers"
const L_Text_Dbg_Msg04_Text        = "In function ListDrivers"
const L_Text_Dbg_Msg05_Text        = "In function ParseCommandLine"

main

'
' Main execution starts here
'
sub main

    dim iAction
    dim iRetval
    dim strServer
    dim strModel
    dim strPath
    dim uVersion
    dim strEnvironment
    dim strInfFile
    dim strUser
    dim strPassword

    '
    ' Abort if the host is not cscript
    '
    if not IsHostCscript() then

        call wscript.echo(L_Help_Help_Host01_Text & vbCRLF & L_Help_Help_Host02_Text & vbCRLF & _
                          L_Help_Help_Host03_Text & vbCRLF & L_Help_Help_Host04_Text & vbCRLF & _
                          L_Help_Help_Host05_Text & vbCRLF & L_Help_Help_Host06_Text & vbCRLF)

        wscript.quit

    end if

    '
    ' Get command line parameters
    '
    iRetval = ParseCommandLine(iAction, strServer, strModel, strPath, uVersion, _
                               strEnvironment, strInfFile, strUser, strPAssword)

    if iRetval = kErrorSuccess  then

        select case iAction

            case kActionAdd
                iRetval = AddDriver(strServer, strModel, strPath, uVersion, _
                                    strEnvironment, strInfFile, strUser, strPassword)

            case kActionDel
                iRetval = DelDriver(strServer, strModel, uVersion, strEnvironment, strUser, strPassword)

            case kActionDelAll
                iRetval = DelAllDrivers(strServer, strUser, strPassword)

            case kActionList
                iRetval = ListDrivers(strServer, strUser, strPassword)

            case kActionUnknown
                Usage(true)
                exit sub

            case else
                Usage(true)
                exit sub

        end select

    end if

end sub

'
' Add a driver
'
function AddDriver(strServer, strModel, strFilePath, uVersion, strEnvironment, strInfFile, strUser, strPassword)

    on error resume next

    DebugPrint kDebugTrace, L_Text_Dbg_Msg01_Text

    dim oDriver
    dim oService
    dim iResult
    dim uResult

    '
    ' Initialize return value
    '
    iResult = kErrorFailure

    if WmiConnect(strServer, kNameSpace, strUser, strPassword, oService) then

        set oDriver = oService.Get("Win32_PrinterDriver")

    else

        AddDriver = kErrorFailure

        exit function

    end if

    '
    ' Check if Get was successful
    '
    if Err.Number = kErrorSuccess then

        oDriver.Name              = strModel
        oDriver.SupportedPlatform = strEnvironment
        oDriver.Version           = uVersion
        oDriver.FilePath          = strFilePath
        oDriver.InfName           = strInfFile

        uResult = oDriver.AddPrinterDriver(oDriver)

        if Err.Number = kErrorSuccess then

            if uResult = kErrorSuccess then

                wscript.echo L_Text_Msg_General01_Text & L_Space_Text & oDriver.Name

                iResult = kErrorSuccess

            else

                wscript.echo L_Text_Msg_General02_Text & L_Space_Text & strModel & L_Space_Text _
                             & L_Text_Error_General03_Text & L_Space_Text & uResult

            end if

        else

            wscript.echo L_Text_Msg_General02_Text & L_Space_Text & strModel & L_Space_Text _
                         & L_Error_Text & L_Space_Text & L_Hex_Text & hex(Err.Number) & L_Space_Text & Err.Description

        end if

    else

        wscript.echo L_Text_Msg_General02_Text & L_Space_Text & strModel & L_Space_Text _
                     & L_Error_Text & L_Space_Text & L_Hex_Text & hex(Err.Number) & L_Space_Text & Err.Description

    end if

    AddDriver = iResult

end function

'
' Delete a driver
'
function DelDriver(strServer, strModel, uVersion, strEnvironment, strUser, strPassword)

    on error resume next

    DebugPrint kDebugTrace, L_Text_Dbg_Msg02_Text

    dim oDriver
    dim oService
    dim iResult
    dim strObject

    '
    ' Initialize return value
    '
    iResult = kErrorFailure

    '
    ' Build the key that identifies the driver instance.
    '
    strObject = strModel & "," & CStr(uVersion) & "," & strEnvironment

    if WmiConnect(strServer, kNameSpace, strUser, strPassword, oService) then

        set oDriver = oService.Get("Win32_PrinterDriver.Name='" & strObject & "'")

    else

        DelDriver = kErrorFailure

        exit function

    end if

    '
    ' Check if Get was successful
    '
    if Err.Number = kErrorSuccess then

        '
        ' Delete the printer driver instance
        '
        oDriver.Delete_

        if Err.Number = kErrorSuccess then

            wscript.echo L_Text_Msg_General04_Text & L_Space_Text & oDriver.Name

            iResult = kErrorSuccess

        else

            wscript.echo L_Text_Msg_General03_Text & L_Space_Text & strModel & L_Space_Text _
                         & L_Error_Text & L_Space_Text & L_Hex_Text & hex(Err.Number) _
                         & L_Space_Text & Err.Description

            call LastError()

        end if

    else

        wscript.echo L_Text_Msg_General03_Text & L_Space_Text & strModel & L_Space_Text _
                     & L_Error_Text & L_Space_Text & L_Hex_Text & hex(Err.Number) _
                     & L_Space_Text & Err.Description

    end if

    DelDriver = iResult

end function

'
' Delete all drivers
'
function DelAllDrivers(strServer, strUser, strPassword)

    on error resume next

    DebugPrint kDebugTrace, L_Text_Dbg_Msg03_Text

    dim Drivers
    dim oDriver
    dim oService
    dim iResult
    dim iTotal
    dim iTotalDeleted
    dim vntDependentFiles
    dim strDriverName

    if WmiConnect(strServer, kNameSpace, strUser, strPassword, oService) then

        set Drivers = oService.InstancesOf("Win32_PrinterDriver")

    else

        DelAllDrivers = kErrorFailure

        exit function

    end if

    if Err.Number <> kErrorSuccess then

        wscript.echo L_Text_Msg_General05_Text & L_Space_Text & L_Error_Text & L_Space_Text _
                     & L_Hex_Text & hex(Err.Number) & L_Space_Text & Err.Description

        DelAllDrivers = kErrorFailure

        exit function

    end if

    iTotal = 0
    iTotalDeleted = 0

    for each oDriver in Drivers

        iTotal = iTotal + 1

        wscript.echo
        wscript.echo L_Text_Msg_General08_Text
        wscript.echo L_Text_Msg_Driver01_Text & L_Space_Text & strServer
        wscript.echo L_Text_Msg_Driver02_Text & L_Space_Text & oDriver.Name
        wscript.echo L_Text_Msg_Driver03_Text & L_Space_Text & oDriver.Version
        wscript.echo L_Text_Msg_Driver04_Text & L_Space_Text & oDriver.SupportedPlatform

        strDriverName = oDriver.Name

        '
        ' Example of how to delete an instance of a printer driver
        '
        oDriver.Delete_

        if Err.Number = kErrorSuccess then

            wscript.echo L_Text_Msg_General04_Text & L_Space_Text & oDriver.Name

            iTotalDeleted = iTotalDeleted + 1

        else

            '
            ' We cannot use oDriver.Name to display the driver name, because the SWbemLastError
            ' that the function LastError() looks at would be overwritten. For that reason we
            ' use strDriverName for accessing the driver name
            '
            wscript.echo L_Text_Msg_General03_Text & L_Space_Text & strDriverName & L_Space_Text _
                         & L_Error_Text & L_Space_Text & L_Hex_Text & hex(Err.Number) _
                         & L_Space_Text & Err.Description

            '
            ' Try getting extended error information
            '
            call LastError()

            Err.Clear

        end if

    next

    wscript.echo L_Empty_Text
    wscript.echo L_Text_Msg_General06_Text & L_Space_Text & iTotal
    wscript.echo L_Text_Msg_General07_Text & L_Space_Text & iTotalDeleted

    DelAllDrivers = kErrorSuccess

end function

'
' List drivers
'
function ListDrivers(strServer, strUser, strPassword)

    on error resume next

    DebugPrint kDebugTrace, L_Text_Dbg_Msg04_Text

    dim Drivers
    dim oDriver
    dim oService
    dim iResult
    dim iTotal
    dim vntDependentFiles

    if WmiConnect(strServer, kNameSpace, strUser, strPassword, oService) then

        set Drivers = oService.InstancesOf("Win32_PrinterDriver")

    else

        ListDrivers = kErrorFailure

        exit function

    end if

    if Err.Number <> kErrorSuccess then

        wscript.echo L_Text_Msg_General05_Text & L_Space_Text & L_Error_Text & L_Space_Text _
                     & L_Hex_Text & hex(Err.Number) & L_Space_Text & Err.Description

        ListDrivers = kErrorFailure

        exit function

    end if

    iTotal = 0

    for each oDriver in Drivers

        iTotal = iTotal + 1

        wscript.echo
        wscript.echo L_Text_Msg_Driver01_Text & L_Space_Text & strServer
        wscript.echo L_Text_Msg_Driver02_Text & L_Space_Text & oDriver.Name
        wscript.echo L_Text_Msg_Driver03_Text & L_Space_Text & oDriver.Version
        wscript.echo L_Text_Msg_Driver04_Text & L_Space_Text & oDriver.SupportedPlatform
        wscript.echo L_Text_Msg_Driver05_Text & L_Space_Text & oDriver.MonitorName
        wscript.echo L_Text_Msg_Driver06_Text & L_Space_Text & oDriver.DriverPath
        wscript.echo L_Text_Msg_Driver07_Text & L_Space_Text & oDriver.DataFile
        wscript.echo L_Text_Msg_Driver08_Text & L_Space_Text & oDriver.ConfigFile
        wscript.echo L_Text_Msg_Driver09_Text & L_Space_Text & oDriver.HelpFile

        vntDependentFiles = oDriver.DependentFiles

        '
        ' If there are no dependent files, the method will set DependentFiles to
        ' an empty variant, so we check if the variant is an array of variants
        '
        if VarType(vntDependentFiles) = (vbArray + vbVariant) then

            PrintDepFiles oDriver.DependentFiles

        end if

        Err.Clear

    next

    wscript.echo L_Empty_Text
    wscript.echo L_Text_Msg_General06_Text & L_Space_Text & iTotal

    ListDrivers = kErrorSuccess

end function

'
' Prints the contents of an array of variants
'
sub PrintDepFiles(Param)

   on error resume next

   dim iIndex

   iIndex = LBound(Param)

   if Err.Number = 0 then

      wscript.echo L_Text_Msg_Driver10_Text

      for iIndex = LBound(Param) to UBound(Param)

          wscript.echo L_Space_Text & Param(iIndex)

      next

   else

        wscript.echo L_Text_Msg_General09_Text & L_Space_Text & L_Error_Text & L_Space_Text _
                     & L_Hex_Text & hex(Err.Number) & L_Space_Text & Err.Description

   end if

end sub

'
' Debug display helper function
'
sub DebugPrint(uFlags, strString)

    if gDebugFlag = true then

        if uFlags = kDebugTrace then

            wscript.echo L_Debug_Text & L_Space_Text & strString

        end if

        if uFlags = kDebugError then

            if Err <> 0 then

                wscript.echo L_Debug_Text & L_Space_Text & strString & L_Space_Text _
                             & L_Error_Text & L_Space_Text & L_Hex_Text & hex(Err.Number) _
                             & L_Space_Text & Err.Description

            end if

        end if

    end if

end sub

'
' Parse the command line into its components
'
function ParseCommandLine(iAction, strServer, strModel, strPath, uVersion, _
                          strEnvironment, strInfFile, strUser, strPassword)

    on error resume next

    DebugPrint kDebugTrace, L_Text_Dbg_Msg05_Text

    dim oArgs
    dim iIndex

    iAction = kActionUnknown
    iIndex = 0

    set oArgs = wscript.Arguments

    while iIndex < oArgs.Count

        select case oArgs(iIndex)

            case "-a"
                iAction = kActionAdd

            case "-d"
                iAction = kActionDel

            case "-l"
                iAction = kActionList

            case "-x"
                iAction = kActionDelAll

            case "-s"
                iIndex = iIndex + 1
                strServer = RemoveBackslashes(oArgs(iIndex))

            case "-m"
                iIndex = iIndex + 1
                strModel = oArgs(iIndex)

            case "-h"
                iIndex = iIndex + 1
                strPath = oArgs(iIndex)

            case "-v"
                iIndex = iIndex + 1
                uVersion = oArgs(iIndex)

            case "-e"
                iIndex = iIndex + 1
                strEnvironment = oArgs(iIndex)

            case "-i"
                iIndex = iIndex + 1
                strInfFile = oArgs(iIndex)

            case "-u"
                iIndex = iIndex + 1
                strUser = oArgs(iIndex)

            case "-w"
                iIndex = iIndex + 1
                strPassword = oArgs(iIndex)

            case "-?"
                Usage(true)
                exit function

            case else
                Usage(true)
                exit function

        end select

        iIndex = iIndex + 1

    wend

    if Err.Number <> 0 then

        wscript.echo L_Text_Error_General02_Text & L_Space_Text & L_Error_Text & L_Space_Text _
                     & L_Hex_Text & hex(Err.Number) & L_Space_text & Err.Description

        ParseCommandLine = kErrorFailure

    else

        ParseCommandLine = kErrorSuccess

    end if

end  function

'
' Display command usage.
'
sub Usage(bExit)

    wscript.echo L_Help_Help_General01_Text
    wscript.echo L_Help_Help_General02_Text
    wscript.echo L_Help_Help_General03_Text
    wscript.echo L_Help_Help_General04_Text
    wscript.echo L_Help_Help_General05_Text
    wscript.echo L_Help_Help_General06_Text
    wscript.echo L_Help_Help_General07_Text
    wscript.echo L_Help_Help_General08_Text
    wscript.echo L_Help_Help_General09_Text
    wscript.echo L_Help_Help_General10_Text
    wscript.echo L_Help_Help_General11_Text
    wscript.echo L_Help_Help_General12_Text
    wscript.echo L_Help_Help_General13_Text
    wscript.echo L_Help_Help_General14_Text
    wscript.echo L_Help_Help_General15_Text
    wscript.echo L_Help_Help_General16_Text
    wscript.echo L_Empty_Text
    wscript.echo L_Help_Help_General17_Text
    wscript.echo L_Help_Help_General18_Text
    wscript.echo L_Help_Help_General19_Text
    wscript.echo L_Help_Help_General20_Text
    wscript.echo L_Help_Help_General21_Text
    wscript.echo L_Help_Help_General22_Text
    wscript.echo L_Help_Help_General23_Text
    wscript.echo L_Help_Help_General24_Text
    wscript.echo L_Help_Help_General25_Text
    wscript.echo L_Help_Help_General26_Text
    wscript.echo L_Empty_Text
    wscript.echo L_Help_Help_General27_Text
    wscript.echo L_Help_Help_General28_Text
    wscript.echo L_Help_Help_General29_Text
    wscript.echo L_Help_Help_General30_Text
    wscript.echo L_Help_Help_General31_Text

    if bExit then

        wscript.quit(1)

    end if

end sub

'
' Determines which program is being used to run this script.
' Returns true if the script host is cscript.exe
'
function IsHostCscript()

    on error resume next

    dim strFullName
    dim strCommand
    dim i, j
    dim bReturn

    bReturn = false

    strFullName = WScript.FullName

    i = InStr(1, strFullName, ".exe", 1)

    if i <> 0 then

        j = InStrRev(strFullName, "\", i, 1)

        if j <> 0 then

            strCommand = Mid(strFullName, j+1, i-j-1)

            if LCase(strCommand) = "cscript" then

                bReturn = true

            end if

        end if

    end if

    if Err <> 0 then

        wscript.echo L_Text_Error_General01_Text & L_Space_Text & L_Error_Text & L_Space_Text _
                     & L_Hex_Text & hex(Err.Number) & L_Space_Text & Err.Description

    end if

    IsHostCscript = bReturn

end function

'
' Retrieves extended information about the last error that occurred
' during a WBEM operation. The methods that set an SWbemLastError
' object are GetObject, PutInstance, DeleteInstance
'
sub LastError()

    on error resume next

    dim oError

    set oError = CreateObject("WbemScripting.SWbemLastError")

    if Err = kErrorSuccess then

        wscript.echo L_Operation_Text            & L_Space_Text & oError.Operation
        wscript.echo L_Provider_Text             & L_Space_Text & oError.ProviderName
        wscript.echo L_Description_Text          & L_Space_Text & oError.Description
        wscript.echo L_Text_Error_General03_Text & L_Space_Text & oError.StatusCode

    end if

end sub

'
' Connects to the WMI service on a server. oService is returned as a service
' object (SWbemServices)
'
function WmiConnect(strServer, strNameSpace, strUser, strPassword, oService)

    on error resume next

    dim oLocator
    dim bResult

    oService = null

    bResult  = false

    set oLocator = CreateObject("WbemScripting.SWbemLocator")

    if Err = kErrorSuccess then

        set oService = oLocator.ConnectServer(strServer, strNameSpace, strUser, strPassword)

        if Err = kErrorSuccess then

            bResult = true

            oService.Security_.impersonationlevel = 3

            '
            ' Required to perform administrative tasks on the spooler service
            '
            oService.Security_.Privileges.AddAsString "SeLoadDriverPrivilege"

            Err.Clear

        else

            wscript.echo L_Text_Msg_General11_Text & L_Space_Text & L_Error_Text _
                         & L_Space_Text & L_Hex_Text & hex(Err.Number) & L_Space_Text _
                         & Err.Description

        end if

    else

        wscript.echo L_Text_Msg_General10_Text & L_Space_Text & L_Error_Text _
                     & L_Space_Text & L_Hex_Text & hex(Err.Number) & L_Space_Text _
                     & Err.Description

    end if

    WmiConnect = bResult

end function

'
' Remove leading "\\" from server name
'
function RemoveBackslashes(strServer)

    dim strRet

    strRet = strServer

    if Left(strServer, 2) = "\\" and Len(strServer) > 2 then

        strRet = Mid(strServer, 3)

    end if

    RemoveBackslashes = strRet

end function


'' SIG '' Begin signature block
'' SIG '' MIIhRgYJKoZIhvcNAQcCoIIhNzCCITMCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' mlUP3KOnaFb8M6G5M6AlnOFVzMN6IRQb2eB8kdGCjCig
'' SIG '' ggrlMIIFBjCCA+6gAwIBAgITMwAAAcQisvebeT2ssgAA
'' SIG '' AAABxDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC
'' SIG '' VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
'' SIG '' B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
'' SIG '' b3JhdGlvbjEuMCwGA1UEAxMlTWljcm9zb2Z0IFdpbmRv
'' SIG '' d3MgUHJvZHVjdGlvbiBQQ0EgMjAxMTAeFw0xODA3MDMy
'' SIG '' MDQ1NTBaFw0xOTA3MjYyMDQ1NTBaMHAxCzAJBgNVBAYT
'' SIG '' AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
'' SIG '' EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
'' SIG '' cG9yYXRpb24xGjAYBgNVBAMTEU1pY3Jvc29mdCBXaW5k
'' SIG '' b3dzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
'' SIG '' AQEAwfWtjHCnvdPp2lQEqkM6KE6YLKTSWeeYzhlmk8fc
'' SIG '' hbVlSrSryRVo6zjdF4kZPIAMIm87bJNg9gLTnEm546XB
'' SIG '' GVtOECIIbJXlT6sM1kKF5b3G8OmA8/YuOV6h2jiSfNuz
'' SIG '' qp5ZbtcFE28m/gkz+es47qSGVaLztTRRbRHIdZi5CUYt
'' SIG '' fX7qwQLbqbJFxSBDTezFmu9zwCDh8/DV8OqfhKAfq4kt
'' SIG '' SYgBADBvHRACpCKigGsokSnVUBtYIiPuvlvSbtSN8wnT
'' SIG '' hqDpH4X6xUfSGKdcZO9YGfB0xyRwThiwjnrzdrHihwJQ
'' SIG '' 9ocHs2OfEfrnJwgaAKd6vOsHhFksjjs3JQmddwIDAQAB
'' SIG '' o4IBgjCCAX4wHwYDVR0lBBgwFgYKKwYBBAGCNwoDBgYI
'' SIG '' KwYBBQUHAwMwHQYDVR0OBBYEFHESAnLIDOuxNR/cbzHv
'' SIG '' Ifyzu0ExMFQGA1UdEQRNMEukSTBHMS0wKwYDVQQLEyRN
'' SIG '' aWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
'' SIG '' ZWQxFjAUBgNVBAUTDTIyOTg3OSs0Mzc5NTQwHwYDVR0j
'' SIG '' BBgwFoAUqSkCOY4WxJd4zZD5nk+a4XxVr1MwVAYDVR0f
'' SIG '' BE0wSzBJoEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQu
'' SIG '' Y29tL3BraW9wcy9jcmwvTWljV2luUHJvUENBMjAxMV8y
'' SIG '' MDExLTEwLTE5LmNybDBhBggrBgEFBQcBAQRVMFMwUQYI
'' SIG '' KwYBBQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
'' SIG '' bS9wa2lvcHMvY2VydHMvTWljV2luUHJvUENBMjAxMV8y
'' SIG '' MDExLTEwLTE5LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
'' SIG '' SIb3DQEBCwUAA4IBAQBncjCj4gTuaosKOOj7/9aAh0QA
'' SIG '' 7u6pAGlTSHA2C9I6SWt+1ZgFuPh6lHAvYxyz8ACW6Nr9
'' SIG '' vKEMUUKS4ROgyfejdit/BKSkP/tyzdGVhW1/CN/d17pA
'' SIG '' ZwRNFNPX2PnALF6RFHjWlAWqV0cSwHmvzylDS4rsuHPo
'' SIG '' nQPlcISCg2Z1VtLGEnSH0BvzYWWXrmEKu1veqvR7CGJz
'' SIG '' yAt6FAu2eABbaj4Ae7agQ4/s+gN5fnS7ioGeAKAZnJkq
'' SIG '' Jh00z/ulRbnAmnZ8/gAXXjriMRmwkW53VioYQKpII2hJ
'' SIG '' 3vWTqY0kNTADbHpz+/vaieRQlZahiUoUiRV2avBlDog7
'' SIG '' L6BrdP4qMIIF1zCCA7+gAwIBAgIKYQd2VgAAAAAACDAN
'' SIG '' BgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
'' SIG '' aWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTExMDE5MTg0
'' SIG '' MTQyWhcNMjYxMDE5MTg1MTQyWjCBhDELMAkGA1UEBhMC
'' SIG '' VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
'' SIG '' B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
'' SIG '' b3JhdGlvbjEuMCwGA1UEAxMlTWljcm9zb2Z0IFdpbmRv
'' SIG '' d3MgUHJvZHVjdGlvbiBQQ0EgMjAxMTCCASIwDQYJKoZI
'' SIG '' hvcNAQEBBQADggEPADCCAQoCggEBAN0Mu6LkLgnj58X3
'' SIG '' lmm8ACG9aTMz760Ey1SA7gaDu8UghNn30ovzOLCrpK0t
'' SIG '' fGJ5Bf/jSj8ENSBw48Tna+CcwDZ16Yox3Y1w5dw3tXRG
'' SIG '' lihbh2AjLL/cR6Vn91EnnnLrB6bJuR47UzV85dPsJ7mH
'' SIG '' HP65ySMJb6hGkcFuljxB08ujP10Cak3saR8lKFw2//1D
'' SIG '' FQqU4Bm0z9/CEuLCWyfuJ3gwi1sqCWsiiVNgFizAaB1T
'' SIG '' uuxJ851hjIVoCXNEXX2iVCvdefcVzzVdbBwrXM68nCOL
'' SIG '' b261Jtk2E8NP1ieuuTI7QZIs4cfNd+iqVE73XAsEh2W0
'' SIG '' QxiosuBtGXfsWiT6SAMCAwEAAaOCAUMwggE/MBAGCSsG
'' SIG '' AQQBgjcVAQQDAgEAMB0GA1UdDgQWBBSpKQI5jhbEl3jN
'' SIG '' kPmeT5rhfFWvUzAZBgkrBgEEAYI3FAIEDB4KAFMAdQBi
'' SIG '' AEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
'' SIG '' /zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
'' SIG '' xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1p
'' SIG '' Y3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
'' SIG '' b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
'' SIG '' AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1p
'' SIG '' Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1
'' SIG '' dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOC
'' SIG '' AgEAFPx8cVGlecJusu85Prw8Ug9uKz8QE3P+qGjQSKY0
'' SIG '' TYqWBSbuMUaQYXnW/zguRWv0wOUouNodj4rbCdcax0wK
'' SIG '' NmZqjOwb1wSQqBgXpJu54kAyNnbEwVrGv+QEwOoW06zD
'' SIG '' aO9irN1UbFAwWKbrfP6Up06O9Ox8hnNXwlIhczRa86OK
'' SIG '' VsgE2gcJ7fiL4870fo6u8PYLigj7P8kdcn9TuOu+Y+Dj
'' SIG '' PTFlsIHl8qzNFqSfPaixm8JC0JCEX1Qd/4nquh1HkG+w
'' SIG '' c05Bn0CfX+WhKrIRkXOKISjwzt5zOV8+q1xg7N8DEKjT
'' SIG '' Cen09paFtn9RiGZHGY2isBI9gSpoBXe7kUxie7bBB8e6
'' SIG '' eoc0Aw5LYnqZ6cr8zko3yS2kV3wc/j3cuA9a+tbEswKF
'' SIG '' Ajrqs9lu5GkhN96B0fZ1GQVn05NXXikbOcjuLeHN5EVz
'' SIG '' W9DSznqrFhmCRljQXp2Bs2evbDXyvOU/JOI1ogp1BvYY
'' SIG '' VpnUeCzRBRvr0IgBnaoQ8QXfun4sY7cGmyMhxPl4bOJY
'' SIG '' FwY2K5ESA8yk2fItuvmUnUDtGEXxzopcaz6rA9NwGCoK
'' SIG '' auBfR9HVYwoy8q/XNh8qcFrlQlkIcUtXun6DgfAhPPQc
'' SIG '' wcW5kJMOiEWThumxIJm+mMvFlaRdYtagYwggvXUQd309
'' SIG '' 80W5n5efy1eAbzOpBM93pGIcWX4xghW5MIIVtQIBATCB
'' SIG '' nDCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
'' SIG '' bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
'' SIG '' FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEuMCwGA1UEAxMl
'' SIG '' TWljcm9zb2Z0IFdpbmRvd3MgUHJvZHVjdGlvbiBQQ0Eg
'' SIG '' MjAxMQITMwAAAcQisvebeT2ssgAAAAABxDANBglghkgB
'' SIG '' ZQMEAgEFAKCCAQQwGQYJKoZIhvcNAQkDMQwGCisGAQQB
'' SIG '' gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
'' SIG '' ARUwLwYJKoZIhvcNAQkEMSIEIHzQ3S/HJfQsF18gElR1
'' SIG '' iwpOGlHP8JWRjg0YO5l6qKz2MDwGCisGAQQBgjcKAxwx
'' SIG '' LgwseWFPZURNbGlWUDdEOUhydVNObWY4eG1YK2s3SkF4
'' SIG '' SG9KcTh4eElrc3Vkdz0wWgYKKwYBBAGCNwIBDDFMMEqg
'' SIG '' JIAiAE0AaQBjAHIAbwBzAG8AZgB0ACAAVwBpAG4AZABv
'' SIG '' AHcAc6EigCBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
'' SIG '' d2luZG93czANBgkqhkiG9w0BAQEFAASCAQB2rNL2XkwP
'' SIG '' HKNsQhn3RVbrbAQ5ecxO6SCtsc8ZEUaILaANZUu6G3gy
'' SIG '' uqKuShJoAqmnI2NLCcPz7Pt/5Ysan4dVmzHn5fgf4fuU
'' SIG '' 9kqjKLfcjPVnWoFFTjgyuagFcfesDlEyotDAUm9O7XCM
'' SIG '' GdFU/iSe5n1gwmD26pLh8ieRto9geWKJu5wWIIMx7/Ux
'' SIG '' w6/KbdT1yPu1mBKT+SdlGdd4JDCfcwec3cb/0P5jrzWc
'' SIG '' i0q6+ybvRuBbxTGDV7YFh+ZZc27b8we6mK3WBC3zafGi
'' SIG '' 2uWM0vDdvsXxTdOqSdkkYVvHinuBbEYwV4gY/MVEB7nE
'' SIG '' p5E2Opj5pY0yBY3ZYnegIxQHoYIS5TCCEuEGCisGAQQB
'' SIG '' gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroC
'' SIG '' AQMxDzANBglghkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJ
'' SIG '' EAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEw
'' SIG '' DQYJYIZIAWUDBAIBBQAEIF16WI8o+5qXc6yE2WH/NOR2
'' SIG '' yzkCaZQFAN4EQXr+1jmOAgZcdB2aU/wYEzIwMTkwMzE5
'' SIG '' MDEyNTE1Ljk0M1owBIACAfSggdCkgc0wgcoxCzAJBgNV
'' SIG '' BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
'' SIG '' VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
'' SIG '' Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
'' SIG '' bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
'' SIG '' cyBUU1MgRVNOOjNCQkQtRTMzOC1FOUExMSUwIwYDVQQD
'' SIG '' ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIO
'' SIG '' PDCCBPEwggPZoAMCAQICEzMAAAD0wKpcc8v+rA8AAAAA
'' SIG '' APQwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMx
'' SIG '' EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
'' SIG '' ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
'' SIG '' dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
'' SIG '' bXAgUENBIDIwMTAwHhcNMTgxMDI0MjExNDI1WhcNMjAw
'' SIG '' MTEwMjExNDI1WjCByjELMAkGA1UEBhMCVVMxEzARBgNV
'' SIG '' BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
'' SIG '' HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEl
'' SIG '' MCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0
'' SIG '' aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JC
'' SIG '' RC1FMzM4LUU5QTExJTAjBgNVBAMTHE1pY3Jvc29mdCBU
'' SIG '' aW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqGSIb3DQEB
'' SIG '' AQUAA4IBDwAwggEKAoIBAQDQY7TeTsdQXJevkSG86VTj
'' SIG '' 2fDLqFYy7WloMrG9n+/ZwdP03lKNqsBIxcdvhp/aSI25
'' SIG '' XDvnp01pjiPV1ZOBNrEs+fJigxIlTpVrX3+awEFty190
'' SIG '' WA+yvHSJMYqWj7IKolH7RUEKVkSj4cWnYiW6HxRRVLVI
'' SIG '' ax0HXh6NX8NpzpSPjPQn3+anbZ3NYGYrzM6ZHsEryFLF
'' SIG '' sKD7/uSQFv9lA993J5wUTE8fW/uaAlFbw/Epjmel9LAQ
'' SIG '' /HgBr/7tYm9UPMPX171LfkRb6jE8MHOaQQekcBO4bgho
'' SIG '' EofBT6r54P9GacguULvU7033MGLQhhGNFIF6mb7jauRg
'' SIG '' KWOJjH7rEljtAgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQU
'' SIG '' nLgfJwcXkbsNIS7ZEufr3IJS9agwHwYDVR0jBBgwFoAU
'' SIG '' 1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBL
'' SIG '' oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
'' SIG '' aS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIwMTAt
'' SIG '' MDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
'' SIG '' BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
'' SIG '' aS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5j
'' SIG '' cnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEF
'' SIG '' BQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAcIPtmx4u2tzi
'' SIG '' Omue9xmTte/lqMzodrmb2F2RijP5kDxaDnuavWnofNtt
'' SIG '' WRVil4jZzLCZEvQKuVIWvW2gVFSawe7zt3GzorjeS49n
'' SIG '' GdzDaVnYRI/baTY24fxF12cEqvNj08PrWNQwhxPuES5x
'' SIG '' OcDIbIOHAeG/ddcXXd7OuW5GNxgus95inCcyF/NdCjrS
'' SIG '' YFTFYZZEM9sDeRomEpdnmWqwj+YL/Ymux0PEjgVbaE28
'' SIG '' CBCeoLJ2/chyvJJFp6YW8DIqZUQYRcQRnLYZwomNbx0r
'' SIG '' L8myEykDnjw6kiPSdf2PfHBzNzeooTxra+/y3X4KTwy+
'' SIG '' lcDIPT0X92wDfUsbwBiGYzCCBnEwggRZoAMCAQICCmEJ
'' SIG '' gSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
'' SIG '' BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
'' SIG '' VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
'' SIG '' Q29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
'' SIG '' b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
'' SIG '' DTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIxNDY1NVowfDEL
'' SIG '' MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
'' SIG '' EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
'' SIG '' c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
'' SIG '' b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqG
'' SIG '' SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs
'' SIG '' /BOX9fp/aZRrdFQQ1aUKAIKF++18aEssX8XD5WHCdrc+
'' SIG '' Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
'' SIG '' DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG
'' SIG '' 8lhHhjKEHnRhZ5FfgVSxz5NMksHEpl3RYRNuKMYa+YaA
'' SIG '' u99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1rL2K
'' SIG '' Qk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox
'' SIG '' 8NpOBpG2iAg16HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4
'' SIG '' zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB4jAQBgkr
'' SIG '' BgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPND
'' SIG '' e3xGG8UzaFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUA
'' SIG '' YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMB
'' SIG '' Af8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
'' SIG '' GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5t
'' SIG '' aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
'' SIG '' Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUF
'' SIG '' BwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5t
'' SIG '' aWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJB
'' SIG '' dXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
'' SIG '' kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFo
'' SIG '' dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3Mv
'' SIG '' Q1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAd
'' SIG '' AEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEA
'' SIG '' dABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4IC
'' SIG '' AQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUxvs8F4qn+
'' SIG '' +ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJE
'' SIG '' Evu5U4zM9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQ
'' SIG '' yK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1L3mBZdmptWvk
'' SIG '' x872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1V
'' SIG '' ry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI5
'' SIG '' 7BlKcWOdeyFtw5yjojz6f32WapB4pm3S4Zz5Hfw42JT0
'' SIG '' xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUP
'' SIG '' ei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw
'' SIG '' 4TtxCd9ddJgiCGHasFAeb73x4QDf5zEHpJM692VHeOj4
'' SIG '' qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
'' SIG '' gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9U
'' SIG '' JyH3yKxO2ii4sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7
'' SIG '' dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp3lfB
'' SIG '' 0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wkn
'' SIG '' HNWzfjUeCLraNtvTX4/edIhJEqGCAs4wggI3AgEBMIH4
'' SIG '' oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
'' SIG '' V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
'' SIG '' A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
'' SIG '' VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
'' SIG '' MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkJELUUz
'' SIG '' MzgtRTlBMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
'' SIG '' U3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAmyMx
'' SIG '' +a+6rCaE0EH3UFeoc6yTGDeggYMwgYCkfjB8MQswCQYD
'' SIG '' VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
'' SIG '' A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
'' SIG '' IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
'' SIG '' VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUF
'' SIG '' AAIFAOA6SxYwIhgPMjAxOTAzMTkwMDUxMzRaGA8yMDE5
'' SIG '' MDMyMDAwNTEzNFowdzA9BgorBgEEAYRZCgQBMS8wLTAK
'' SIG '' AgUA4DpLFgIBADAKAgEAAgIpQQIB/zAHAgEAAgIRojAK
'' SIG '' AgUA4DuclgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
'' SIG '' BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYag
'' SIG '' MA0GCSqGSIb3DQEBBQUAA4GBAGsMNcBaT+WihRwYU5qS
'' SIG '' GqFwpxdR6HBX3XEmiBHHR2mvD6eJq1BDwk5+s2CxLJEd
'' SIG '' HxB44EpqAUTxVbFAQFjWWsiwT+C4j9UkVUBL5hjy2cGv
'' SIG '' PQZCG1WfBCYOSF7fUr4QclVS+lo2dURu9tbWzuFRiGSK
'' SIG '' coZf5pJ9nC/FBRSzeo7zMYIDDTCCAwkCAQEwgZMwfDEL
'' SIG '' MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
'' SIG '' EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
'' SIG '' c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
'' SIG '' b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAD0wKpc
'' SIG '' c8v+rA8AAAAAAPQwDQYJYIZIAWUDBAIBBQCgggFKMBoG
'' SIG '' CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
'' SIG '' 9w0BCQQxIgQg+5fsrL2Tbg8hoRL92XDIm2iWxaslxhh1
'' SIG '' ZF9ZDloT5kQwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
'' SIG '' MIG9BCA6By8tCMiCbaETbRxKjjaJems5eLv16IdLu50l
'' SIG '' jOIy1zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
'' SIG '' VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
'' SIG '' MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
'' SIG '' JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
'' SIG '' QSAyMDEwAhMzAAAA9MCqXHPL/qwPAAAAAAD0MCIEIC8U
'' SIG '' k0v3MaEXqTFWNaTy9b06+L88bfeRSHtxBwdv1CUoMA0G
'' SIG '' CSqGSIb3DQEBCwUABIIBAIBee3eqc1xcaPceZvAMzalg
'' SIG '' QPVaXKR19sbq4YIFJiv7JdXBVXZp9oonjj6rFWbZSvHD
'' SIG '' SdPmDvhd+F9RUgscwVBTboqtGOzv5B6l5a2B3xYO+fG+
'' SIG '' UKFTlt/BG61wWtP1ocuMNBe91y57n7Dx9EH7FYU1Vbqs
'' SIG '' qW2SpSWqUfan2P9etzBeASncAdjUj/NOAALC9ZXrURPJ
'' SIG '' k9U9UQPde2UASmRbB9QlCuejYcTLiTi4m1Ldv32+gHzz
'' SIG '' 8kKtby5uoxsvHh2XZm4DaQw3aZq90GmlhENUgMeFPgwi
'' SIG '' nYgRVMlVV9IfCibGYiCHa2o+7qGEGP1JN6zjn/XQQf4C
'' SIG '' f4FSHS5D2Ms=
'' SIG '' End signature block
