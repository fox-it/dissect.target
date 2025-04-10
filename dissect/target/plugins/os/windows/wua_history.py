from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.esedb.c_esedb import decode_guid
from dissect.esedb.esedb import EseDB
from dissect.util.ts import oatimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.target.target import Target

WuaHistoryRecord = TargetRecordDescriptor(
    "filesystem/windows/wua_history",
    [
        ("datetime", "ts"),
        ("varint", "id_event"),
        ("varint", "status"),
        ("varint", "server_selection"),
        ("string", "mapped_result"),
        ("string", "unmapped_result"),
        ("string", "update_id"),
        ("string", "server_id"),
        ("varint", "flags"),
        ("string", "client_id"),
        ("string", "title"),
        ("string", "description"),
        ("string", "uninstall_notes"),
        ("string", "support_url"),
        ("string", "uninstall_steps"),
        ("string", "categories"),
        ("string", "more_info_url"),
        ("string", "path"),
        ("varint", "id_user"),
        ("string", "is_service_is_additional"),
        ("string", "classification"),
        # Enriched fields
        ("string", "kb"),
        ("string", "status_mapped"),
        ("string", "mapped_result_string"),
        ("string", "mapped_result_description"),
        ("string", "unmapped_result_string"),
        ("string", "unmapped_result_description"),
        ("string", "server_id_mapped"),
        ("string", "server_selection_mapped"),
        ("string", "classification_mapped"),
    ],
)

TBHISTORY_COLUMN_MAP = {
    "IdEvent": "id_event",
    "Status": "status",
    "ServerSelection": "server_selection",
    "MappedResult": "mapped_result",
    "UnmappedResult": "unmapped_result",
    "UpdateId": "update_id",
    "ServerId": "server_id",
    "Date": "ts",
    "Flags": "flags",
    "ClientId": "client_id",
    "Title": "title",
    "Description": "description",
    "UninstallNotes": "uninstall_notes",
    "SupportUrl": "support_url",
    "UninstallSteps": "uninstall_steps",
    "Categories": "categories",
    "MoreInfoUrl": "more_info_url",
    "IdUser": "id_user",
    "IsServiceIsAdditional": "is_service_is_additional",
    "Classification": "classification",
    # Enriched fields
    "kb": "kb",
    "status_mapped": "status_mapped",
    "mapped_result_string": "mapped_result_string",
    "mapped_result_description": "mapped_result_description",
    "unmapped_result_string": "unmapped_result_string",
    "unmapped_result_description": "unmapped_result_description",
    "server_id_mapped": "server_id_mapped",
    "server_selection_mapped": "server_selection_mapped",
    "classification_mapped": "classification_mapped",
}

CLASSIFICATION_MAP = {
    "5c9376ab-8ce6-464a-b136-22113dd69801": "Application",
    "434de588-ed14-48f5-8eed-a15e09a991f6": "Connectors",
    "e6cf1350-c01b-414d-a61f-263d14d133b4": "CriticalUpdates",
    "e0789628-ce08-4437-be74-2495b842f43b": "DefinitionUpdates",
    "e140075d-8433-45c3-ad87-e72345b36078": "DeveloperKits",
    "b54e7d24-7add-428f-8b75-90a396fa584f": "FeaturePacks",
    "9511d615-35b2-47bb-927f-f73d8e9260bb": "Guidance",
    "0fa1201d-4330-4fa8-8ae9-b877473b6441": "SecurityUpdates",
    "68c5b0a3-d1a6-4553-ae49-01d3a7827828": "ServicePacks",
    "b4832bd8-e735-4761-8daf-37f882276dab": "Tools",
    "28bc880e-0592-4cbf-8f95-c79b17911d5f": "UpdateRollups",
    "cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83": "Updates",
    "3689bdc8-b205-4af4-8d4a-a63924c5e9d5": "Upgrades",
    "ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0": "Drivers",
}

SERVER_ID_MAP = {
    "00000000-0000-0000-0000-000000000000": "Unspecified / Default",
    "9482f4b4-e343-43b6-b170-9a65bc822c77": "Windows Update",
    "7971f918-a847-4430-9279-4a52d1efe18d": "Microsoft Update",
    "855e8a7c-ecb4-4ca3-b045-1dfa50104289": "Store",
    "8b24b027-1dee-babb-9a95-3517dfb9c552": "OS Flighting",
    "3da21691-e39d-4da6-8a4b-b43877bcb1b7": "WSUS or Configuration Manager",
}

SERVER_SELECTION_MAP = {
    0: "ssDefault",
    1: "ssManagedServer",
    2: "ssWindowsUpdate",
    3: "ssOthers",
}

STATUS_MAP = {
    1: "Success",
    2: "Failure",
}

WUA_CODE_MAP = {
    "0x0": ["Success", "Success"],
    "0x240001": ["WU_S_SERVICE_STOP", "Windows Update Agent was stopped successfully."],
    "0x240002": ["WU_S_SELFUPDATE", "Windows Update Agent updated itself."],
    "0x240003": ["WU_S_UPDATE_ERROR", "Operation completed successfully but there were errors applying the updates."],
    "0x240004": [
        "WU_S_MARKED_FOR_DISCONNECT",
        "A callback was marked to be disconnected later because the request to disconnect the operation came while a"
        " callback was executing.",
    ],
    "0x240005": ["WU_S_REBOOT_REQUIRED", "The system must be restarted to complete installation of the update."],
    "0x240006": ["WU_S_ALREADY_INSTALLED", "The update to be installed is already installed on the system."],
    "0x240007": ["WU_S_ALREADY_UNINSTALLED", "The update to be removed is not installed on the system."],
    "0x240008": ["WU_S_ALREADY_DOWNLOADED", "The update to be downloaded has already been downloaded."],
    "0x8024400A": [
        "WU_E_PT_SOAPCLIENT_PARSE",
        "SOAPCLIENT_PARSE_ERROR - SOAP client failed to parse the response from the server.",
    ],
    "0x8024600a": [
        "WU_E_DM_DOWNLOADLOCATIONCHANGED",
        "A download must be restarted because the location of the source of the download has changed.",
    ],
    "0x8024D008": [
        "WU_E_SELFUPDATE_SKIP_ON_FAILURE",
        "An update to the Windows Update Agent was skipped because previous attempts to update have failed.",
    ],
    "0x8024D011": ["WU_E_SELFUPDATE_REQUIRED", "Windows Update Agent must be updated before search can continue."],
    "0x8024D012": [
        "WU_E_SELFUPDATE_REQUIRED_ADMIN",
        "Windows Update Agent must be updated before search can continue. An administrator is required to perform the "
        "operation",
    ],
    "0x80243FFF": [
        "WU_E_AUCLIENT_UNEXPECTED",
        "There was a user interface error not covered by another WU_E_AUCLIENT_* error code.",
    ],
    "0x8024A000": ["WU_E_AU_NOSERVICE", "Automatic Updates was unable to service incoming requests."],
    "0x8024A002": [
        "WU_E_AU_NONLEGACYSERVER",
        "The old version of the Automatic Updates client has stopped because the WSUS server has been upgraded.",
    ],
    "0x8024A003": ["WU_E_AU_LEGACYCLIENTDISABLED", "The old version of the Automatic Updates client was disabled."],
    "0x8024A004": [
        "WU_E_AU_PAUSED",
        "Automatic Updates was unable to process incoming requests because it was paused.",
    ],
    "0x8024A005": ["WU_E_AU_NO_REGISTERED_SERVICE", "No unmanaged service is registered with AU."],
    "0x8024AFFF": ["WU_E_AU_UNEXPECTED", "An Automatic Updates error not covered by another WU_E_AU * code."],
    "0x80243001": [
        "WU_E_INSTALLATION_RESULTS_UNKNOWN_VERSION",
        "The results of download and installation could not be read from the registry due to an unrecognized data "
        "format version.",
    ],
    "0x80243002": [
        "WU_E_INSTALLATION_RESULTS_INVALID_DATA",
        "The results of download and installation could not be read from the registry due to an invalid data format.",
    ],
    "0x80243003": [
        "WU_E_INSTALLATION_RESULTS_NOT_FOUND",
        "The results of download and installation are not available; the operation may have failed to start.",
    ],
    "0x80243004": [
        "WU_E_TRAYICON_FAILURE",
        "A failure occurred when trying to create an icon in the taskbar notification area.",
    ],
    "0x80243FFD": [
        "WU_E_NON_UI_MODE",
        "Unable to show UI when in non-UI mode; WU client UI modules may not be installed.",
    ],
    "0x80243FFE": ["WU_E_WUCLTUI_UNSUPPORTED_VERSION", "Unsupported version of WU client UI exported functions."],
    "0x8024043D": ["WU_E_SERVICEPROP_NOTAVAIL", "The requested service property isn't available."],
    "0x80249001": ["WU_E_INVENTORY_PARSEFAILED", "Parsing of the rule file failed."],
    "0x80249002": [
        "WU_E_INVENTORY_GET_INVENTORY_TYPE_FAILED",
        "Failed to get the requested inventory type from the server.",
    ],
    "0x80249003": ["WU_E_INVENTORY_RESULT_UPLOAD_FAILED", "Failed to upload inventory result to the server."],
    "0x80249004": ["WU_E_INVENTORY_UNEXPECTED", "There was an inventory error not covered by another error code."],
    "0x80249005": [
        "WU_E_INVENTORY_WMI_ERROR",
        "A WMI error occurred when enumerating the instances for a particular class.",
    ],
    "0x8024E001": [
        "WU_E_EE_UNKNOWN_EXPRESSION",
        "An expression evaluator operation could not be completed because an expression was unrecognized.",
    ],
    "0x8024E002": [
        "WU_E_EE_INVALID_EXPRESSION",
        "An expression evaluator operation could not be completed because an expression was invalid.",
    ],
    "0x8024E003": [
        "WU_E_EE_MISSING_METADATA",
        "An expression evaluator operation could not be completed because an expression contains an incorrect number "
        "of metadata nodes.",
    ],
    "0x8024E004": [
        "WU_E_EE_INVALID_VERSION",
        "An expression evaluator operation could not be completed because the version of the serialized expression "
        "data is invalid.",
    ],
    "0x8024E005": ["WU_E_EE_NOT_INITIALIZED", "The expression evaluator could not be initialized."],
    "0x8024E006": [
        "WU_E_EE_INVALID_ATTRIBUTEDATA",
        "An expression evaluator operation could not be completed because there was an invalid attribute.",
    ],
    "0x8024E007": [
        "WU_E_EE_CLUSTER_ERROR",
        "An expression evaluator operation could not be completed because the cluster state of the computer could not "
        "be determined.",
    ],
    "0x8024EFFF": [
        "WU_E_EE_UNEXPECTED",
        "There was an expression evaluator error not covered by another WU_E_EE_* error code.",
    ],
    "0x80247001": [
        "WU_E_OL_INVALID_SCANFILE",
        "An operation could not be completed because the scan package was invalid.",
    ],
    "0x80247002": [
        "WU_E_OL_NEWCLIENT_REQUIRED",
        "An operation could not be completed because the scan package requires a greater version of the Windows Update "
        "Agent.",
    ],
    "0x80247FFF": ["WU_E_OL_UNEXPECTED", "Search using the scan package failed."],
    "0x8024F001": ["WU_E_REPORTER_EVENTCACHECORRUPT", "The event cache file was defective."],
    "0x8024F002": [
        "WU_E_REPORTER_",
        "EVENTNAMESPACEPARSEFAILEDThe XML in the event namespace descriptor could not be parsed.",
    ],
    "0x8024F003": ["WU_E_INVALID_EVENT", "The XML in the event namespace descriptor could not be parsed."],
    "0x8024F004": ["WU_E_SERVER_BUSY", "The server rejected an event because the server was too busy."],
    "0x8024FFFF": ["WU_E_REPORTER_UNEXPECTED", "There was a reporter error not covered by another error code."],
    "0x80245001": ["WU_E_REDIRECTOR_LOAD_XML", "The redirector XML document could not be loaded into the DOM class."],
    "0x80245002": ["WU_E_REDIRECTOR_S_FALSE", "The redirector XML document is missing some required information."],
    "0x80245003": [
        "WU_E_REDIRECTOR_ID_SMALLER",
        "The redirector ID in the downloaded redirector cab is less than in the cached cab.",
    ],
    "0x80245FFF": [
        "WU_E_REDIRECTOR_UNEXPECTED",
        "The redirector failed for reasons not covered by another WU_E_REDIRECTOR_* error code.",
    ],
    "0x80244000": [
        "WU_E_PT_SOAPCLIENT_BASE",
        "WU_E_PT_SOAPCLIENT_* error codes map to the SOAPCLIENT_ERROR enum of the ATL Server Library.",
    ],
    "0x80244001": [
        "WU_E_PT_SOAPCLIENT_INITIALIZE",
        "SOAPCLIENT_INITIALIZE_ERROR - initialization of the SOAP client failed, possibly because of an MSXML "
        "installation failure.",
    ],
    "0x80244002": [
        "WU_E_PT_SOAPCLIENT_OUTOFMEMORY",
        "SOAPCLIENT_OUTOFMEMORY - SOAP client failed because it ran out of memory.",
    ],
    "0x80244003": [
        "WU_E_PT_SOAPCLIENT_GENERATE",
        "SOAPCLIENT_GENERATE_ERROR - SOAP client failed to generate the request.",
    ],
    "0x80244004": [
        "WU_E_PT_SOAPCLIENT_CONNECT",
        "SOAPCLIENT_CONNECT_ERROR - SOAP client failed to connect to the server.",
    ],
    "0x80244005": [
        "WU_E_PT_SOAPCLIENT_SEND",
        "SOAPCLIENT_SEND_ERROR - SOAP client failed to send a message for reasons of WU_E_WINHTTP_* error codes.",
    ],
    "0x80244006": [
        "WU_E_PT_SOAPCLIENT_SERVER",
        "SOAPCLIENT_SERVER_ERROR - SOAP client failed because there was a server error.",
    ],
    "0x80244007": [
        "WU_E_PT_SOAPCLIENT_SOAPFAULT",
        "SOAPCLIENT_SOAPFAULT - SOAP client failed because there was a SOAP fault for reasons of WU_E_PT_SOAP_* error "
        "codes.",
    ],
    "0x80244008": [
        "WU_E_PT_SOAPCLIENT_PARSEFAULT",
        "SOAPCLIENT_PARSEFAULT_ERROR - SOAP client failed to parse a SOAP fault.",
    ],
    "0x80244009": [
        "WU_E_PT_SOAPCLIENT_READ",
        "SOAPCLIENT_READ_ERROR - SOAP client failed while reading the response from the server.",
    ],
    "x8024400A": [
        "WU_E_PT_SOAPCLIENT_PARSE",
        "Same as SOAPCLIENT_PARSE_ERROR - SOAP client failed to parse the response from the server.",
    ],
    "0x8024400B": [
        "WU_E_PT_SOAP_VERSION",
        "SOAP_E_VERSION_MISMATCH - SOAP client found an unrecognizable namespace for the SOAP envelope.",
    ],
    "0x8024400C": [
        "WU_E_PT_SOAP_MUST_UNDERSTAND",
        "SOAP_E_MUST_UNDERSTAND - SOAP client was unable to understand a header.",
    ],
    "0x8024400D": [
        "WU_E_PT_SOAP_CLIENT",
        "SOAP_E_CLIENT - SOAP client found the message was malformed; fix before resending.",
    ],
    "0x8024400E": [
        "WU_E_PT_SOAP_SERVER",
        "SOAP_E_SERVER - The SOAP message could not be processed due to a server error; resend later.",
    ],
    "0x8024400F": ["WU_E_PT_WMI_ERROR", "There was an unspecified Windows Management Instrumentation (WMI) error."],
    "0x80244010": [
        "WU_E_PT_EXCEEDED_MAX_SERVER_TRIPS",
        "The number of round trips to the server exceeded the maximum limit.",
    ],
    "0x80244011": ["WU_E_PT_SUS_SERVER_NOT_SET", "WUServer policy value is missing in the registry."],
    "0x80244012": [
        "WU_E_PT_DOUBLE_INITIALIZATION",
        "Initialization failed because the object was already initialized.",
    ],
    "0x80244013": ["WU_E_PT_INVALID_COMPUTER_NAME", "The computer name could not be determined."],
    "0x80244015": [
        "WU_E_PT_REFRESH_CACHE_REQUIRED",
        "The reply from the server indicates that the server was changed or the cookie was invalid; refresh the state "
        "of the internal cache and retry.",
    ],
    "0x80244016": [
        "WU_E_PT_HTTP_STATUS_BAD_REQUEST",
        "HTTP 400 - the server could not process the request due to invalid syntax.",
    ],
    "0x80244017": ["WU_E_PT_HTTP_STATUS_DENIED", "HTTP 401 - the requested resource requires user authentication."],
    "0x80244018": [
        "WU_E_PT_HTTP_STATUS_FORBIDDEN",
        "HTTP 403 - server understood the request, but declined to fulfill it.",
    ],
    "0x80244019": [
        "WU_E_PT_HTTP_STATUS_NOT_FOUND",
        "HTTP 404 - the server cannot find the requested URI (Uniform Resource Identifier).",
    ],
    "0x8024401A": ["WU_E_PT_HTTP_STATUS_BAD_METHOD", "HTTP 405 - the HTTP method is not allowed."],
    "0x8024401B": ["WU_E_PT_HTTP_STATUS_PROXY_AUTH_REQ", "HTTP 407 - proxy authentication is required."],
    "0x8024401C": ["WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT", "HTTP 408 - the server timed out waiting for the request."],
    "0x8024401D": [
        "WU_E_PT_HTTP_STATUS_CONFLICT",
        "HTTP 409 - the request was not completed due to a conflict with the current state of the resource.",
    ],
    "0x8024401E": ["WU_E_PT_HTTP_STATUS_GONE", "HTTP 410 - requested resource is no longer available at the server."],
    "0x8024401F": [
        "WU_E_PT_HTTP_STATUS_SERVER_ERROR",
        "HTTP 500 - an error internal to the server prevented fulfilling the request.",
    ],
    "0x80244020": [
        "WU_E_PT_HTTP_STATUS_NOT_SUPPORTED",
        "HTTP 501 - server does not support the functionality required to fulfill the request.",
    ],
    "0x80244021": [
        "WU_E_PT_HTTP_STATUS_BAD_GATEWAY",
        "HTTP 502 - the server, while acting as a gateway or proxy, received an invalid response from the upstream "
        "server it accessed in attempting to fulfill the request.",
    ],
    "0x80244022": ["WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL", "HTTP 503 - the service is temporarily overloaded."],
    "0x80244023": [
        "WU_E_PT_HTTP_STATUS_GATEWAY_TIMEOUT",
        "HTTP 504 - the request was timed out waiting for a gateway.",
    ],
    "0x80244024": [
        "WU_E_PT_HTTP_STATUS_VERSION_NOT_SUP",
        "HTTP 505 - the server does not support the HTTP protocol version used for the request.",
    ],
    "0x80244025": [
        "WU_E_PT_FILE_LOCATIONS_CHANGED",
        "Operation failed due to a changed file location; refresh internal state and resend.",
    ],
    "0x80244026": [
        "WU_E_PT_REGISTRATION_NOT_SUPPORTED",
        "Operation failed because Windows Update Agent does not support registration with a non-WSUS server.",
    ],
    "0x80244027": [
        "WU_E_PT_NO_AUTH_PLUGINS_REQUESTED",
        "The server returned an empty authentication information list.",
    ],
    "0x80244028": [
        "WU_E_PT_NO_AUTH_COOKIES_CREATED",
        "Windows Update Agent was unable to create any valid authentication cookies.",
    ],
    "0x80244029": ["WU_E_PT_INVALID_CONFIG_PROP", "A configuration property value was wrong."],
    "0x8024402A": ["WU_E_PT_CONFIG_PROP_MISSING", "A configuration property value was missing."],
    "0x8024402B": [
        "WU_E_PT_HTTP_STATUS_NOT_MAPPED",
        "The HTTP request could not be completed and the reason did not correspond to any of the WU_E_PT_HTTP_* error "
        "codes.",
    ],
    "0x8024402C": [
        "WU_E_PT_WINHTTP_NAME_NOT_RESOLVED",
        "ERROR_WINHTTP_NAME_NOT_RESOLVED - the proxy server or target server name cannot be resolved.",
    ],
    "0x8024402F": ["WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS", "External cab file processing completed with some errors."],
    "0x80244030": ["WU_E_PT_ECP_INIT_FAILED", "The external cab processor initialization did not complete."],
    "0x80244031": ["WU_E_PT_ECP_INVALID_FILE_FORMAT", "The format of a metadata file was invalid."],
    "0x80244032": ["WU_E_PT_ECP_INVALID_METADATA", "External cab processor found invalid metadata."],
    "0x80244033": [
        "WU_E_PT_ECP_FAILURE_TO_EXTRACT_DIGEST",
        "The file digest could not be extracted from an external cab file.",
    ],
    "0x80244034": ["WU_E_PT_ECP_FAILURE_TO_DECOMPRESS_CAB_FILE", "An external cab file could not be decompressed."],
    "0x80244035": ["WU_E_PT_ECP_FILE_LOCATION_ERROR", "External cab processor was unable to get file locations."],
    "0x80244FFF": ["WU_E_PT_UNEXPECTED", "A communication error not covered by another WU_E_PT_* error code"],
    "0x8024502D": [
        "WU_E_PT_SAME_REDIR_ID",
        "Windows Update Agent failed to download a redirector cabinet file with a new redirector ID value from the "
        "server during the recovery.",
    ],
    "0x8024502E": [
        "WU_E_PT_NO_MANAGED_RECOVER",
        "A redirector recovery action did not complete because the server is managed.",
    ],
    "0x80246001": [
        "WU_E_DM_URLNOTAVAILABLE",
        "A download manager operation could not be completed because the requested file does not have a URL.",
    ],
    "0x80246002": [
        "WU_E_DM_INCORRECTFILEHASH",
        "A download manager operation could not be completed because the file digest was not recognized.",
    ],
    "0x80246003": [
        "WU_E_DM_UNKNOWNALGORITHM",
        "A download manager operation could not be completed because the file metadata requested an unrecognized hash "
        "algorithm.",
    ],
    "0x80246004": [
        "WU_E_DM_NEEDDOWNLOADREQUEST",
        "An operation could not be completed because a download request is required from the download handler.",
    ],
    "0x80246005": [
        "WU_E_DM_NONETWORK",
        "A download manager operation could not be completed because the network connection was unavailable.",
    ],
    "0x80246006": [
        "WU_E_DM_WRONGBITSVERSION",
        "A download manager operation could not be completed because the version of Background Intelligent Transfer "
        "Service (BITS) is incompatible.",
    ],
    "0x80246007": ["WU_E_DM_NOTDOWNLOADED", "The update has not been downloaded."],
    "0x80246008": [
        "WU_E_DM_FAILTOCONNECTTOBITS",
        "A download manager operation failed because the download manager was unable to connect the Background "
        "Intelligent Transfer Service (BITS).",
    ],
    "0x80246009": [
        "WU_E_DM_BITSTRANSFERERROR",
        "A download manager operation failed because there was an unspecified Background Intelligent Transfer Service "
        "(BITS) transfer error.",
    ],
    "0x8024600A": [
        "WU_E_DM_DOWNLOADLOCATIONCHANGED",
        "A download must be restarted because the location of the source of the download has changed.",
    ],
    "0x8024600B": [
        "WU_E_DM_CONTENTCHANGED",
        "A download must be restarted because the update content changed in a new revision.",
    ],
    "0x80246FFF": [
        "WU_E_DM_UNEXPECTED",
        "There was a download manager error not covered by another WU_E_DM_* error code.",
    ],
    "0x80242000": [
        "WU_E_UH_REMOTEUNAVAILABLE",
        "A request for a remote update handler could not be completed because no remote process is available.",
    ],
    "0x80242001": [
        "WU_E_UH_LOCALONLY",
        "A request for a remote update handler could not be completed because the handler is local only.",
    ],
    "0x80242002": [
        "WU_E_UH_UNKNOWNHANDLER",
        "A request for an update handler could not be completed because the handler could not be recognized.",
    ],
    "0x80242003": [
        "WU_E_UH_REMOTEALREADYACTIVE",
        "A remote update handler could not be created because one already exists.",
    ],
    "0x80242004": [
        "WU_E_UH_DOESNOTSUPPORTACTION",
        "A request for the handler to install (uninstall) an update could not be completed because the update does not "
        "support install (uninstall).",
    ],
    "0x80242005": ["WU_E_UH_WRONGHANDLER", "An operation did not complete because the wrong handler was specified."],
    "0x80242006": [
        "WU_E_UH_INVALIDMETADATA",
        "A handler operation could not be completed because the update contains invalid metadata.",
    ],
    "0x80242007": [
        "WU_E_UH_INSTALLERHUNG",
        "An operation could not be completed because the installer exceeded the time limit.",
    ],
    "0x80242008": ["WU_E_UH_OPERATIONCANCELLED", "An operation being done by the update handler was cancelled."],
    "0x80242009": [
        "WU_E_UH_BADHANDLERXML",
        "An operation could not be completed because the handler-specific metadata is invalid.",
    ],
    "0x8024200A": [
        "WU_E_UH_CANREQUIREINPUT",
        "A request to the handler to install an update could not be completed because the update requires user input.",
    ],
    "0x8024200B": ["WU_E_UH_INSTALLERFAILURE", "The installer failed to install (uninstall) one or more updates."],
    "0x8024200C": [
        "WU_E_UH_FALLBACKTOSELFCONTAINED",
        "The update handler should download self-contained content rather than delta-compressed content for the "
        "update.",
    ],
    "0x8024200D": [
        "WU_E_UH_NEEDANOTHERDOWNLOAD",
        "The update handler did not install the update because it needs to be downloaded again.",
    ],
    "0x8024200E": [
        "WU_E_UH_NOTIFYFAILURE",
        "The update handler failed to send notification of the status of the install (uninstall) operation.",
    ],
    "0x8024200F": [
        "WU_E_UH_INCONSISTENT_FILE_NAMES",
        "The file names contained in the update metadata and in the update package are inconsistent.",
    ],
    "0x80242010": ["WU_E_UH_FALLBACKERROR", "The update handler failed to fall back to the self-contained content."],
    "0x80242011": [
        "WU_E_UH_TOOMANYDOWNLOADREQUESTS",
        "The update handler has exceeded the maximum number of download requests.",
    ],
    "0x80242012": ["WU_E_UH_UNEXPECTEDCBSRESPONSE", "The update handler has received an unexpected response from CBS."],
    "0x80242013": ["WU_E_UH_BADCBSPACKAGEID", "The update metadata contains an invalid CBS package identifier."],
    "0x80242014": ["WU_E_UH_POSTREBOOTSTILLPENDING", "The post-reboot operation for the update is still in progress."],
    "0x80242015": [
        "WU_E_UH_POSTREBOOTRESULTUNKNOWN",
        "The result of the post-reboot operation for the update could not be determined.",
    ],
    "0x80242016": [
        "WU_E_UH_POSTREBOOTUNEXPECTEDSTATE",
        "The state of the update after its post-reboot operation has completed is unexpected.",
    ],
    "0x80242017": [
        "WU_E_UH_NEW_SERVICING_STACK_REQUIRED",
        "The operating system servicing stack must be updated before this update is downloaded or installed.",
    ],
    "0x80242FFF": ["WU_E_UH_UNEXPECTED", "An update handler error not covered by another WU_E_UH_* code."],
    "0x80248000": ["WU_E_DS_SHUTDOWN", "An operation failed because Windows Update Agent is shutting down."],
    "0x80248001": ["WU_E_DS_INUSE", "An operation failed because the data store was in use."],
    "0x80248002": ["WU_E_DS_INVALID", "The current and expected states of the data store do not match."],
    "0x80248003": ["WU_E_DS_TABLEMISSING", "The data store is missing a table."],
    "0x80248004": ["WU_E_DS_TABLEINCORRECT", "The data store contains a table with unexpected columns."],
    "0x80248005": [
        "WU_E_DS_INVALIDTABLENAME",
        "A table could not be opened because the table is not in the data store.",
    ],
    "0x80248006": ["WU_E_DS_BADVERSION", "The current and expected versions of the data store do not match."],
    "0x80248007": ["WU_E_DS_NODATA", "The information requested is not in the data store."],
    "0x80248008": [
        "WU_E_DS_MISSINGDATA",
        "The data store is missing required information or has a NULL in a table column that requires a non-null "
        "value.",
    ],
    "0x80248009": [
        "WU_E_DS_MISSINGREF",
        "The data store is missing required information or has a reference to missing license terms, file, localized "
        "property or linked row.",
    ],
    "0x8024800A": [
        "WU_E_DS_UNKNOWNHANDLER",
        "The update was not processed because its update handler could not be recognized.",
    ],
    "0x8024800B": [
        "WU_E_DS_CANTDELETE",
        "The update was not deleted because it is still referenced by one or more services.",
    ],
    "0x8024800C": [
        "WU_E_DS_LOCKTIMEOUTEXPIRED",
        "The data store section could not be locked within the allotted time.",
    ],
    "0x8024800D": [
        "WU_E_DS_NOCATEGORIES",
        "The category was not added because it contains no parent categories and is not a top-level category itself.",
    ],
    "0x8024800E": ["WU_E_DS_ROWEXISTS", "The row was not added because an existing row has the same primary key."],
    "0x8024800F": [
        "WU_E_DS_STOREFILELOCKED",
        "The data store could not be initialized because it was locked by another process.",
    ],
    "0x80248010": [
        "WU_E_DS_CANNOTREGISTER",
        "The data store is not allowed to be registered with COM in the current process.",
    ],
    "0x80248011": ["WU_E_DS_UNABLETOSTART", "Could not create a data store object in another process."],
    "0x80248013": [
        "WU_E_DS_DUPLICATEUPDATEID",
        "The server sent the same update to the client with two different revision IDs.",
    ],
    "0x80248014": [
        "WU_E_DS_UNKNOWNSERVICE",
        "An operation did not complete because the service is not in the data store.",
    ],
    "0x80248015": [
        "WU_E_DS_SERVICEEXPIRED",
        "An operation did not complete because the registration of the service has expired.",
    ],
    "0x80248016": [
        "WU_E_DS_DECLINENOTALLOWED",
        "A request to hide an update was declined because it is a mandatory update or because it was deployed with a "
        "deadline.",
    ],
    "0x80248017": [
        "WU_E_DS_TABLESESSIONMISMATCH",
        "A table was not closed because it is not associated with the session.",
    ],
    "0x80248018": [
        "WU_E_DS_SESSIONLOCKMISMATCH",
        "A table was not closed because it is not associated with the session.",
    ],
    "0x80248019": [
        "WU_E_DS_NEEDWINDOWSSERVICE",
        "A request to remove the Windows Update service or to unregister it with Automatic Updates was declined "
        "because it is a built-in service and/or Automatic Updates cannot fall back to another service.",
    ],
    "0x8024801A": ["WU_E_DS_INVALIDOPERATION", "A request was declined because the operation is not allowed."],
    "0x8024801B": [
        "WU_E_DS_SCHEMAMISMATCH",
        "The schema of the current data store and the schema of a table in a backup XML document do not match.",
    ],
    "0x8024801C": [
        "WU_E_DS_RESETREQUIRED",
        "The data store requires a session reset; release the session and retry with a new session.",
    ],
    "0x8024801D": [
        "WU_E_DS_IMPERSONATED",
        "A data store operation did not complete because it was requested with an impersonated identity.",
    ],
    "0x80248FFF": ["WU_E_DS_UNEXPECTED", "A data store error not covered by another WU_E_DS_* code."],
    "0x8024C001": ["WU_E_DRV_PRUNED", "A driver was skipped."],
    "0x8024C002": [
        "WU_E_DRV_NOPROP_OR_LEGACY",
        "A property for the driver could not be found. It may not conform with required specifications.",
    ],
    "0x8024C003": ["WU_E_DRV_REG_MISMATCH", "The registry type read for the driver does not match the expected type."],
    "0x8024C004": ["WU_E_DRV_NO_METADATA", "The driver update is missing metadata."],
    "0x8024C005": ["WU_E_DRV_MISSING_ATTRIBUTE", "The driver update is missing a required attribute."],
    "0x8024C006": ["WU_E_DRV_SYNC_FAILED", "Driver synchronization failed."],
    "0x8024C007": [
        "WU_E_DRV_NO_PRINTER_CONTENT",
        "Information required for the synchronization of applicable printers is missing.",
    ],
    "0x8024CFFF": ["WU_E_DRV_UNEXPECTED", "A driver error not covered by another WU_E_DRV_* code."],
    "0x80240001": ["WU_E_NO_SERVICE", "Windows Update Agent was unable to provide the service."],
    "0x80240002": ["WU_E_MAX_CAPACITY_REACHED", "The maximum capacity of the service was exceeded."],
    "0x80240003": ["WU_E_UNKNOWN_ID", "An ID cannot be found."],
    "0x80240004": ["WU_E_NOT_INITIALIZED", "The object could not be initialized."],
    "0x80240005": [
        "WU_E_RANGEOVERLAP",
        "The update handler requested a byte range overlapping a previously requested range.",
    ],
    "0x80240006": ["WU_E_TOOMANYRANGES", "The requested number of byte ranges exceeds the maximum number (2^31 - 1)."],
    "0x80240007": ["WU_E_INVALIDINDEX", "The index to a collection was invalid."],
    "0x80240008": ["WU_E_ITEMNOTFOUND", "The key for the item queried could not be found."],
    "0x80240009": [
        "WU_E_OPERATIONINPROGRESS",
        "Another conflicting operation was in progress. Some operations such as installation cannot be performed twice "
        "simultaneously.",
    ],
    "0x8024000A": ["WU_E_COULDNOTCANCEL", "Cancellation of the operation was not allowed."],
    "0x8024000B": ["WU_E_CALL_CANCELLED", "Operation was cancelled."],
    "0x8024000C": ["WU_E_NOOP", "No operation was required."],
    "0x8024000D": [
        "WU_E_XML_MISSINGDATA",
        "Windows Update Agent could not find required information in the update's XML data.",
    ],
    "0x8024000E": ["WU_E_XML_INVALID", "Windows Update Agent found invalid information in the update's XML data."],
    "0x8024000F": ["WU_E_CYCLE_DETECTED", "Circular update relationships were detected in the metadata."],
    "0x80240010": ["WU_E_TOO_DEEP_RELATION", "Update relationships too deep to evaluate were evaluated."],
    "0x80240011": ["WU_E_INVALID_RELATIONSHIP", "An invalid update relationship was detected."],
    "0x80240012": ["WU_E_REG_VALUE_INVALID", "An invalid registry value was read."],
    "0x80240013": ["WU_E_DUPLICATE_ITEM", "Operation tried to add a duplicate item to a list."],
    "0x80240016": [
        "WU_E_INSTALL_NOT_ALLOWED",
        "Operation tried to install while another installation was in progress or the system was pending a mandatory "
        "restart.",
    ],
    "0x80240017": ["WU_E_NOT_APPLICABLE", "Operation was not performed because there are no applicable updates."],
    "0x80240018": ["WU_E_NO_USERTOKEN", "Operation failed because a required user token is missing."],
    "0x80240019": [
        "WU_E_EXCLUSIVE_INSTALL_CONFLICT",
        "An exclusive update cannot be installed with other updates at the same time.",
    ],
    "0x8024001A": ["WU_E_POLICY_NOT_SET", "A policy value was not set."],
    "0x8024001B": [
        "WU_E_SELFUPDATE_IN_PROGRESS",
        "The operation could not be performed because the Windows Update Agent is self-updating.",
    ],
    "0x8024001D": ["WU_E_INVALID_UPDATE", "An update contains invalid metadata."],
    "0x8024001E": [
        "WU_E_SERVICE_STOP",
        "Operation did not complete because the service or system was being shut down.",
    ],
    "0x8024001F": ["WU_E_NO_CONNECTION", "Operation did not complete because the network connection was unavailable."],
    "0x80240020": [
        "WU_E_NO_INTERACTIVE_USER",
        "Operation did not complete because there is no logged-on interactive user.",
    ],
    "0x80240021": ["WU_E_TIME_OUT", "Operation did not complete because it timed out."],
    "0x80240022": ["WU_E_ALL_UPDATES_FAILED", "Operation failed for all the updates."],
    "0x80240023": ["WU_E_EULAS_DECLINED", "The license terms for all updates were declined."],
    "0x80240024": ["WU_E_NO_UPDATE", "There are no updates."],
    "0x80240025": ["WU_E_USER_ACCESS_DISABLED", "Group Policy settings prevented access to Windows Update."],
    "0x80240026": ["WU_E_INVALID_UPDATE_TYPE", "The type of update is invalid."],
    "0x80240027": ["WU_E_URL_TOO_LONG", "The URL exceeded the maximum length."],
    "0x80240028": [
        "WU_E_UNINSTALL_NOT_ALLOWED",
        "The update could not be uninstalled because the request did not originate from a WSUS server.",
    ],
    "0x80240029": [
        "WU_E_INVALID_PRODUCT_LICENSE",
        "Search may have missed some updates before there is an unlicensed application on the system.",
    ],
    "0x8024002A": ["WU_E_MISSING_HANDLER", "A component required to detect applicable updates was missing."],
    "0x8024002B": ["WU_E_LEGACYSERVER", "An operation did not complete because it requires a newer version of server."],
    "0x8024002C": [
        "WU_E_BIN_SOURCE_ABSENT",
        "A delta-compressed update could not be installed because it required the source.",
    ],
    "0x8024002D": ["WU_E_SOURCE_ABSENT", "A full-file update could not be installed because it required the source."],
    "0x8024002E": ["WU_E_WU_DISABLED", "Access to an unmanaged server is not allowed."],
    "0x8024002F": [
        "WU_E_CALL_CANCELLED_BY_POLICY",
        "Operation did not complete because the DisableWindowsUpdateAccess policy was set.",
    ],
    "0x80240030": ["WU_E_INVALID_PROXY_SERVER", "The format of the proxy list was invalid."],
    "0x80240031": ["WU_E_INVALID_FILE", "The file is in the wrong format."],
    "0x80240032": ["WU_E_INVALID_CRITERIA", "The search criteria string was invalid."],
    "0x80240033": ["WU_E_EULA_UNAVAILABLE", "License terms could not be downloaded."],
    "0x80240034": ["WU_E_DOWNLOAD_FAILED", "Update failed to download."],
    "0x80240035": ["WU_E_UPDATE_NOT_PROCESSED", "The update was not processed."],
    "0x80240036": ["WU_E_INVALID_OPERATION", "The object's current state did not allow the operation."],
    "0x80240037": ["WU_E_NOT_SUPPORTED", "The functionality for the operation is not supported."],
    "0x80240038": ["WU_E_WINHTTP_INVALID_FILE", "The downloaded file has an unexpected content type."],
    "0x80240039": ["WU_E_TOO_MANY_RESYNC", "Agent is asked by server to resync too many times."],
    "0x80240040": ["WU_E_NO_SERVER_CORE_SUPPORT", "WUA API method does not run on Server Core installation."],
    "0x80240041": ["WU_E_SYSPREP_IN_PROGRESS", "Service is not available while sysprep is running."],
    "0x80240042": ["WU_E_UNKNOWN_SERVICE", "The update service is no longer registered with AU."],
    "0x80240043": ["WU_E_NO_UI_SUPPORT", "There's no support for WUA UI."],
    "0x80240FFF": ["WU_E_UNEXPECTED", "An operation failed due to reasons not covered by another error code."],
    "0x80070422": ["NA", "This issue occurs when the Windows Update service stops working or isn't running."],
    "0x00240001": ["WU_S_SERVICE_STOP", "Windows Update Agent was stopped successfully."],
    "0x00240002": ["WU_S_SELFUPDATE", "Windows Update Agent updated itself."],
    "0x00240003": ["WU_S_UPDATE_ERROR", "Operation completed successfully but there were errors applying the updates."],
    "0x00240004": [
        "WU_S_MARKED_FOR_DISCONNECT",
        "A callback was marked to be disconnected later because the request to disconnect the operation came while a "
        "callback was executing.",
    ],
    "0x00240005": ["WU_S_REBOOT_REQUIRED", "The system must be restarted to complete installation of the update."],
    "0x00240006": ["WU_S_ALREADY_INSTALLED", "The update to be installed is already installed on the system."],
    "0x00240007": ["WU_S_ALREADY_UNINSTALLED", "The update to be removed isn't installed on the system."],
    "0x00240008": ["WU_S_ALREADY_DOWNLOADED", "The update to be downloaded has already been downloaded."],
    "0x80241001": [
        "WU_E_MSI_WRONG_VERSION",
        "Search may have missed some updates because the Windows Installer is less than version 3.1.",
    ],
    "0x80241002": [
        "WU_E_MSI_NOT_CONFIGURED",
        "Search may have missed some updates because the Windows Installer is not configured.",
    ],
    "0x80241003": [
        "WU_E_MSP_DISABLED",
        "Search may have missed some updates because policy has disabled Windows Installer patching.",
    ],
    "0x80241004": [
        "WU_E_MSI_WRONG_APP_CONTEXT",
        "An update could not be applied because the application is installed per-user.",
    ],
    "0x80241FFF": [
        "WU_E_MSP_UNEXPECTED",
        "Search may have missed some updates because there was a failure of the Windows Installer.",
    ],
    "0x8024D001": [
        "WU_E_SETUP_INVALID_INFDATA",
        "Windows Update Agent could not be updated because an INF file contains invalid information.",
    ],
    "0x8024D002": [
        "WU_E_SETUP_INVALID_IDENTDATA",
        "Windows Update Agent could not be updated because the wuident.cab file contains invalid information.",
    ],
    "0x8024D003": [
        "WU_E_SETUP_ALREADY_INITIALIZED",
        "Windows Update Agent could not be updated because of an internal error that caused setup initialization to be "
        "performed twice.",
    ],
    "0x8024D004": [
        "WU_E_SETUP_NOT_INITIALIZED",
        "Windows Update Agent could not be updated because setup initialization never completed successfully.",
    ],
    "0x8024D005": [
        "WU_E_SETUP_SOURCE_VERSION_MISMATCH",
        "Windows Update Agent could not be updated because the versions specified in the INF do not match the actual "
        "source file versions.",
    ],
    "0x8024D006": [
        "WU_E_SETUP_TARGET_VERSION_GREATER",
        "Windows Update Agent could not be updated because a WUA file on the target system is newer than the "
        "corresponding source file.",
    ],
    "0x8024D007": [
        "WU_E_SETUP_REGISTRATION_FAILED",
        "Windows Update Agent could not be updated because regsvr32.exe returned an error.",
    ],
    "0x8024D009": [
        "WU_E_SETUP_SKIP_UPDATE",
        "An update to the Windows Update Agent was skipped due to a directive in the wuident.cab file.",
    ],
    "0x8024D00A": [
        "WU_E_SETUP_UNSUPPORTED_CONFIGURATION",
        "Windows Update Agent could not be updated because the current system configuration is not supported.",
    ],
    "0x8024D00B": [
        "WU_E_SETUP_BLOCKED_CONFIGURATION",
        "Windows Update Agent could not be updated because the system is configured to block the update.",
    ],
    "0x8024D00C": [
        "WU_E_SETUP_REBOOT_TO_FIX",
        "Windows Update Agent could not be updated because a restart of the system is required.",
    ],
    "0x8024D00D": ["WU_E_SETUP_ALREADYRUNNING", "Windows Update Agent setup is already running."],
    "0x8024D00E": [
        "WU_E_SETUP_REBOOTREQUIRED",
        "Windows Update Agent setup package requires a reboot to complete installation.",
    ],
    "0x8024D00F": [
        "WU_E_SETUP_HANDLER_EXEC_FAILURE",
        "Windows Update Agent could not be updated because the setup handler failed during execution.",
    ],
    "0x8024D010": [
        "WU_E_SETUP_INVALID_REGISTRY_DATA",
        "Windows Update Agent could not be updated because the registry contains invalid information.",
    ],
    "0x8024D013": [
        "WU_E_SETUP_WRONG_SERVER_VERSION",
        "Windows Update Agent could not be updated because the server does not contain update information for this "
        "version.",
    ],
    "0x8024DFFF": [
        "WU_E_SETUP_UNEXPECTED",
        "Windows Update Agent could not be updated because of an error not covered by another WU_E_SETUP_* error code.",
    ],
    "0x80070BC9": [
        "ERROR_FAIL_REBOOT_REQUIRED",
        "The requested operation failed. Restart the system to roll back changes made.",
    ],
    "0x80200053": ["BG_E_VALIDATION_FAILED", "NA"],
    "0x80072EFD": ["TIME_OUT_ERRORS", "The operation timed out"],
    "0x80072EFE": [
        "WININET_E_CONNECTION_ABORTED; The connection with the server was closed abnormally",
        "BITS is unable to transfer the file successfully.",
    ],
    "0x80D02002": ["TIME_OUT_ERRORS", "The operation timed out"],
    "0X8007000D": ["ERROR_INVALID_DATA", "Indicates data that isn't valid was downloaded or corruption occurred."],
    "0x8024A10A": ["USO_E_SERVICE_SHUTTING_DOWN", "Indicates that the Windows Update Service is shutting down."],
    "0x80246017": [
        "WU_E_DM_UNAUTHORIZED_LOCAL_USER",
        "The download failed because the local user was denied authorization to download the content.",
    ],
    "0x800f0821": [
        "CBS_E_ABORT; client abort, IDABORT returned by ICbsUIHandler method except Error()",
        "CBS transaction timeout exceeded.",
    ],
    "0x800f0825": [
        "CBS_E_CANNOT_UNINSTALL; Package can't be uninstalled.",
        "Typically this error is due component store corruption caused when a component is in a partially installed "
        "state.",
    ],
    "0x800F0920": [
        "CBS_E_HANG_DETECTED; A failure to respond was detected while processing the operation.",
        "Subsequent error logged after getting 0x800f0821",
    ],
    "0x800f081f": [
        "CBS_E_SOURCE_MISSING; source for package or file not found, ResolveSource() unsuccessful",
        "Component Store corruption",
    ],
    "0x800f0831": ["CBS_E_STORE_CORRUPTION; CBS store is corrupted.", "Corruption in the Windows Component Store."],
    "0x80070005": [
        "E_ACCESSDENIED; General access denied error",
        "File system or registry key permissions have been changed and the servicing stack doesn't have the required "
        "level of access.",
    ],
    "0x80070003": [
        "ERROR_PATH_NOT_FOUND; The system can't find the path specified.",
        "The servicing stack can't access a specific path.",
    ],
    "0x80073701": [
        "ERROR_SXS_ASSEMBLY_MISSING; The referenced assembly couldn't be found.",
        "Typically, a component store corruption caused when a component is in a partially installed state.",
    ],
    "0x80072F8F": [
        "WININET_E_DECODING_FAILED; Content decoding has failed",
        "TLS 1.2 isn't configured correctly on the client.",
    ],
    "0x80072EE2": [
        "WININET_E_TIMEOUT; The operation timed out",
        "Unable to scan for updates due to a connectivity issue to Windows Update, Configuration Manager, or WSUS.",
    ],
    "0x80070490": ["ERROR_NOT_FOUND", "This error occurs during driver installation as part of the update."],
    "0x800f0922": [
        "CBS_E_INSTALLERS_FAILED",
        "The July cumulative update failed to be installed on Windows Server 2016",
    ],
    "0x80070bc9": [
        "ERROR_FAIL_REBOOT_REQUIRED",
        "The TrustedInstaller service startup type is set to 'Manual' by Group Policy (GPO), which prevented it from "
        "starting to complete pending operations.",
    ],
    "0x800706be": [
        "Failed to install cumulative updates",
        "Windows Server 2016 Std failed to install cumulative packages by using the .msu package. No error is "
        "returned. When installing the packages with dism.exe, it returned the error 0x800706be.",
    ],
}


class WuaHistoryPlugin(Plugin):
    """Plugin to return all available historical Windows Update Agent operations stored in the DataStore.edb."""

    DATASTORE_PATH = "sysvol/windows/softwaredistribution/datastore/datastore.edb"
    DATASTORE_UPDATE_TABLE = "tbHistory"

    def __init__(self, target: Target):
        super().__init__(target)

        self._datastore = None
        self._update_table = None

        if (path := target.fs.path(self.DATASTORE_PATH)).exists():
            try:
                self._datastore = EseDB(path.open())
                self._update_table = self._datastore.table(self.DATASTORE_UPDATE_TABLE)
            except Exception as e:
                self.target.log.warning("Error opening Windows Update Agent datastore")
                self.target.log.debug("", exc_info=e)

    def check_compatible(self) -> None:
        if not self._datastore or not self._update_table:
            raise UnsupportedPluginError("No Windows Update Agent data found.")

    def get_table_records(self) -> Iterator[dict[str, str | int | datetime]]:
        for record in self._update_table.records():
            record_data = {}
            for column in self._update_table.columns:
                column_value = record.get(column.name)

                if mapped_column_name := TBHISTORY_COLUMN_MAP.get(column.name):
                    if mapped_column_name in "unmapped_result":
                        column_value = hex(int(column_value) & 0xFFFFFFFF)

                        info = WUA_CODE_MAP.get(column_value, ["Unknown", "Unknown"])
                        record_data[f"{mapped_column_name}_description"] = info[0]
                        record_data[f"{mapped_column_name}_string"] = info[1]

                    record_data.update(self._format_record_value(mapped_column_name, column_value))

            yield record_data

    @export(record=WuaHistoryRecord)
    def wua_history(self) -> Iterator[WuaHistoryRecord]:
        """Returns all available historical Windows Update Agent operations stored in the DataStore.edb.

        The Windows Update Agent (WUA) stores information of its operations in a DataStore.edb file.
        Historical data of these operations, successful or failed performed patches, are stored in the 'tbHistory' table
        of this database. The plugin extracts all rows of this table. For certain columns of the table the extracted
        data is mapped to publicly available enumerations to provide more meaningful information.

        With this plugin you should be able to ascertain the patch level of systems, and it may aid you into
        finding why a system was generating a lot of other types of events in a certain time period.

        References:
            - https://learn.microsoft.com/en-us/windows/deployment/update/how-windows-update-works
            - https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatehistoryentry
            - https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-error-reference
            - https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/common-windows-update-errors
            - https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/common-windows-update-errors?context=%2Fwindows%2Fdeployment%2Fcontext%2Fcontext
            - https://github.com/libyal/esedb-kb/blob/main/documentation/Windows%20Update.asciidoc
            - https://www.nirsoft.net/articles/extract-windows-updates-list-external-drive.html

        Yields a WuaHistoryRecord with fields:

        .. code-block:: text

            ts (datetime): The timestamp (UTC) of when the Windows Update Agent operation was finished.
            categories (string): Category of the update.
            classification (string): Unique ID indicating which classification the update has.
            classification_mapped (string): Mapping of the 'classification' field, giving an understandable classification.
            client_id (string): Client that initiated the Windows Update Agent operation.
            description (string): Description of the update.
            flags (int): Undocumented and unknown.
            id_event (int): Index number of the Windows Update Agent record in the tbHistory table.
            kb (string): Another unique ID of the update.
            status (int): Integer signifying result of operation
            status_mapped (string): Mapping of the 'status' field.
            server_selection (int): The update service that was used for the Windows Update Agent operation.
            server_selection_mapped (string): Mapping of the 'server_selection' field.
            title (string): Title of the update.
            mapped_result (string): The mapped result code of an update operation.
            mapped_result_string (string): Mapping of the 'mapped_result' field, giving the error string.
            mapped_result_description (string): Mapping of the 'mapped_result' field, giving a description of the error.
            unmapped_result (string): The unmapped result code of an update operation.
            unmapped_result_string (string): Mapping of the 'unmapped_result' field, giving the error string.
            unmapped_result_description (string): Mapping of the 'unmapped_result' field, giving a description of the error.
            update_id (string): Unique ID of the performed update.
            server_id (string): Unique ID of the service used for the update operation.
            server_id_mapped (string): Mapping of the 'server_id' field, indication the service used for the update operation.
            support_url (string): Support URL of the update.
            uninstall_notes (string): Uninstall notes of the update.
            uninstall_steps (string): Uninstall steps of the update.
            more_info_url (string): Additional informational URLs of the update.
            path (uri): Path of the datastore containing the Windows Update Agent records.
            id_user (int): Undocumented and unknown.
            is_service_is_additional (string): Undocumented and unknown.
        """  # noqa: E501
        for record in self.get_table_records():
            values = {TBHISTORY_COLUMN_MAP.get(key, key): value for key, value in record.items()}

            yield WuaHistoryRecord(
                **values,
                path=self.target.fs.path(self.DATASTORE_PATH),
                _target=self.target,
            )

    def _format_record_value(self, mapped_column_name: str, value: str) -> dict[str, str | int | datetime]:
        format_data = {}

        if mapped_column_name == "ts":
            format_data[mapped_column_name] = oatimestamp(value)
        elif mapped_column_name == "update_id":
            format_data[mapped_column_name] = decode_guid(value[:16])
        elif mapped_column_name == "server_id":
            guid = decode_guid(value[:16])
            format_data[mapped_column_name] = guid
            format_data["server_id_mapped"] = SERVER_ID_MAP.get(guid, "Unknown")
        elif mapped_column_name == "classification":
            format_data[mapped_column_name] = value
            format_data["classification_mapped"] = CLASSIFICATION_MAP.get(value, "Unknown")
        elif mapped_column_name == "title":
            format_data[mapped_column_name] = value
            if kb := re.search(r"(KB.[0-9]*)", value):
                format_data["kb"] = kb.group()
        elif mapped_column_name == "status":
            format_data[mapped_column_name] = value
            format_data["status_mapped"] = STATUS_MAP.get(value, "Unknown")
        elif mapped_column_name == "server_selection":
            key = value - 1
            format_data[mapped_column_name] = key
            format_data["server_selection_mapped"] = SERVER_SELECTION_MAP.get(key, "Unknown")
        else:
            format_data[mapped_column_name] = value

        return format_data
