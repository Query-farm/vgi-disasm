//! Compiled-in **reference data** for the heuristic capability matcher (§B): the
//! curated import-name → ATT&CK and string → ATT&CK tables.
//!
//! These are intentionally shipped as data (here, as `const` Rust tables — no
//! external file or parser, so the build stays bounded and the ruleset is
//! auditable in one place). Each entry is `{pattern, rule, attack_id,
//! attack_name, severity}`. ATT&CK technique IDs/names are an open catalog used
//! as reference data (`source_url` → attack.mitre.org). This is **not** capa:
//! no scoring, no rule composition, no basic-block features.

/// `(pattern, rule, attack_id, attack_name, severity)`.
pub type MapEntry = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

/// Import API name (exact, case-insensitive) → technique. Curated to the
/// well-known malware surface; extend here, the matcher stays thin.
pub const API_MAP: &[MapEntry] = &[
    // T1055 Process Injection.
    (
        "VirtualAllocEx",
        "inject:VirtualAllocEx",
        "T1055",
        "Process Injection",
        "high",
    ),
    (
        "WriteProcessMemory",
        "inject:WriteProcessMemory",
        "T1055",
        "Process Injection",
        "high",
    ),
    (
        "CreateRemoteThread",
        "inject:CreateRemoteThread",
        "T1055",
        "Process Injection",
        "high",
    ),
    (
        "NtCreateThreadEx",
        "inject:NtCreateThreadEx",
        "T1055",
        "Process Injection",
        "high",
    ),
    (
        "QueueUserAPC",
        "inject:QueueUserAPC",
        "T1055.004",
        "Process Injection: Asynchronous Procedure Call",
        "high",
    ),
    (
        "RtlCreateUserThread",
        "inject:RtlCreateUserThread",
        "T1055",
        "Process Injection",
        "high",
    ),
    (
        "VirtualProtect",
        "inject:VirtualProtect",
        "T1055",
        "Process Injection",
        "medium",
    ),
    (
        "VirtualProtectEx",
        "inject:VirtualProtectEx",
        "T1055",
        "Process Injection",
        "medium",
    ),
    (
        "SetThreadContext",
        "inject:SetThreadContext",
        "T1055.012",
        "Process Injection: Process Hollowing",
        "high",
    ),
    // T1547.001 Registry Run Keys.
    (
        "RegSetValueExA",
        "persist:RegSetValueEx",
        "T1547.001",
        "Boot or Logon Autostart Execution: Registry Run Keys",
        "medium",
    ),
    (
        "RegSetValueExW",
        "persist:RegSetValueEx",
        "T1547.001",
        "Boot or Logon Autostart Execution: Registry Run Keys",
        "medium",
    ),
    (
        "RegCreateKeyExA",
        "persist:RegCreateKeyEx",
        "T1112",
        "Modify Registry",
        "low",
    ),
    (
        "RegCreateKeyExW",
        "persist:RegCreateKeyEx",
        "T1112",
        "Modify Registry",
        "low",
    ),
    // T1071 Application Layer Protocol (C2 / networking).
    (
        "InternetOpenUrlA",
        "net:InternetOpenUrl",
        "T1071",
        "Application Layer Protocol",
        "medium",
    ),
    (
        "InternetOpenUrlW",
        "net:InternetOpenUrl",
        "T1071",
        "Application Layer Protocol",
        "medium",
    ),
    (
        "InternetConnectA",
        "net:InternetConnect",
        "T1071",
        "Application Layer Protocol",
        "medium",
    ),
    (
        "InternetConnectW",
        "net:InternetConnect",
        "T1071",
        "Application Layer Protocol",
        "medium",
    ),
    (
        "WinHttpOpen",
        "net:WinHttpOpen",
        "T1071",
        "Application Layer Protocol",
        "medium",
    ),
    (
        "WinHttpConnect",
        "net:WinHttpConnect",
        "T1071",
        "Application Layer Protocol",
        "medium",
    ),
    (
        "URLDownloadToFileA",
        "net:URLDownloadToFile",
        "T1105",
        "Ingress Tool Transfer",
        "high",
    ),
    (
        "URLDownloadToFileW",
        "net:URLDownloadToFile",
        "T1105",
        "Ingress Tool Transfer",
        "high",
    ),
    (
        "socket",
        "net:socket",
        "T1071",
        "Application Layer Protocol",
        "low",
    ),
    (
        "connect",
        "net:connect",
        "T1071",
        "Application Layer Protocol",
        "low",
    ),
    (
        "WSAStartup",
        "net:WSAStartup",
        "T1071",
        "Application Layer Protocol",
        "low",
    ),
    // T1486 Data Encrypted for Impact (ransomware).
    (
        "CryptEncrypt",
        "crypto:CryptEncrypt",
        "T1486",
        "Data Encrypted for Impact",
        "high",
    ),
    (
        "BCryptEncrypt",
        "crypto:BCryptEncrypt",
        "T1486",
        "Data Encrypted for Impact",
        "high",
    ),
    (
        "CryptAcquireContextA",
        "crypto:CryptAcquireContext",
        "T1486",
        "Data Encrypted for Impact",
        "low",
    ),
    (
        "CryptAcquireContextW",
        "crypto:CryptAcquireContext",
        "T1486",
        "Data Encrypted for Impact",
        "low",
    ),
    // T1622 Debugger Evasion.
    (
        "IsDebuggerPresent",
        "antidbg:IsDebuggerPresent",
        "T1622",
        "Debugger Evasion",
        "medium",
    ),
    (
        "CheckRemoteDebuggerPresent",
        "antidbg:CheckRemoteDebuggerPresent",
        "T1622",
        "Debugger Evasion",
        "medium",
    ),
    (
        "NtQueryInformationProcess",
        "antidbg:NtQueryInformationProcess",
        "T1622",
        "Debugger Evasion",
        "low",
    ),
    // T1134 Access Token Manipulation.
    (
        "AdjustTokenPrivileges",
        "token:AdjustTokenPrivileges",
        "T1134",
        "Access Token Manipulation",
        "medium",
    ),
    (
        "OpenProcessToken",
        "token:OpenProcessToken",
        "T1134",
        "Access Token Manipulation",
        "low",
    ),
    (
        "LookupPrivilegeValueA",
        "token:LookupPrivilegeValue",
        "T1134",
        "Access Token Manipulation",
        "low",
    ),
    (
        "LookupPrivilegeValueW",
        "token:LookupPrivilegeValue",
        "T1134",
        "Access Token Manipulation",
        "low",
    ),
    // T1056.001 Input Capture: Keylogging.
    (
        "SetWindowsHookExA",
        "keylog:SetWindowsHookEx",
        "T1056.001",
        "Input Capture: Keylogging",
        "medium",
    ),
    (
        "SetWindowsHookExW",
        "keylog:SetWindowsHookEx",
        "T1056.001",
        "Input Capture: Keylogging",
        "medium",
    ),
    (
        "GetAsyncKeyState",
        "keylog:GetAsyncKeyState",
        "T1056.001",
        "Input Capture: Keylogging",
        "medium",
    ),
    (
        "GetKeyState",
        "keylog:GetKeyState",
        "T1056.001",
        "Input Capture: Keylogging",
        "low",
    ),
    // T1059 Command and Scripting Interpreter (execution).
    (
        "ShellExecuteA",
        "exec:ShellExecute",
        "T1059",
        "Command and Scripting Interpreter",
        "medium",
    ),
    (
        "ShellExecuteW",
        "exec:ShellExecute",
        "T1059",
        "Command and Scripting Interpreter",
        "medium",
    ),
    (
        "WinExec",
        "exec:WinExec",
        "T1059",
        "Command and Scripting Interpreter",
        "medium",
    ),
    (
        "CreateProcessA",
        "exec:CreateProcess",
        "T1106",
        "Native API",
        "low",
    ),
    (
        "CreateProcessW",
        "exec:CreateProcess",
        "T1106",
        "Native API",
        "low",
    ),
    // T1106 Native API / dynamic resolution.
    (
        "LoadLibraryA",
        "loader:LoadLibrary",
        "T1106",
        "Native API",
        "info",
    ),
    (
        "LoadLibraryW",
        "loader:LoadLibrary",
        "T1106",
        "Native API",
        "info",
    ),
    (
        "GetProcAddress",
        "loader:GetProcAddress",
        "T1106",
        "Native API",
        "info",
    ),
    // T1497 Sandbox/timing evasion (API form).
    (
        "GetTickCount",
        "antivm:GetTickCount",
        "T1497",
        "Virtualization/Sandbox Evasion",
        "low",
    ),
    // T1083 File and Directory Discovery.
    (
        "FindFirstFileA",
        "discover:FindFirstFile",
        "T1083",
        "File and Directory Discovery",
        "info",
    ),
    (
        "FindFirstFileW",
        "discover:FindFirstFile",
        "T1083",
        "File and Directory Discovery",
        "info",
    ),
    // T1543.003 Windows Service / T1053.005 Scheduled Task.
    (
        "CreateServiceA",
        "persist:CreateService",
        "T1543.003",
        "Create or Modify System Process: Windows Service",
        "medium",
    ),
    (
        "CreateServiceW",
        "persist:CreateService",
        "T1543.003",
        "Create or Modify System Process: Windows Service",
        "medium",
    ),
];

/// Interesting-string substring (matched case-insensitively) → technique.
pub const STRING_MAP: &[MapEntry] = &[
    (
        "powershell",
        "exec:powershell",
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
        "medium",
    ),
    (
        "-encodedcommand",
        "exec:powershell_enc",
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
        "high",
    ),
    (
        " -enc ",
        "exec:powershell_enc",
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
        "high",
    ),
    (
        "cmd.exe /c",
        "exec:cmd",
        "T1059.003",
        "Command and Scripting Interpreter: Windows Command Shell",
        "medium",
    ),
    (
        "cmd /c",
        "exec:cmd",
        "T1059.003",
        "Command and Scripting Interpreter: Windows Command Shell",
        "medium",
    ),
    (
        "schtasks",
        "persist:schtasks",
        "T1053.005",
        "Scheduled Task/Job: Scheduled Task",
        "medium",
    ),
    (
        "currentversion\\run",
        "persist:run_key",
        "T1547.001",
        "Boot or Logon Autostart Execution: Registry Run Keys",
        "high",
    ),
    (
        "\\\\.\\pipe\\",
        "ipc:named_pipe",
        "T1559",
        "Inter-Process Communication",
        "low",
    ),
    (
        "http://",
        "net:url",
        "T1071",
        "Application Layer Protocol",
        "info",
    ),
    (
        "https://",
        "net:url",
        "T1071",
        "Application Layer Protocol",
        "info",
    ),
    (
        ".onion",
        "net:tor",
        "T1090.003",
        "Proxy: Multi-hop Proxy",
        "high",
    ),
    (
        "your files have been encrypted",
        "ransom:note",
        "T1486",
        "Data Encrypted for Impact",
        "high",
    ),
    (
        "vmware",
        "antivm:vmware",
        "T1497.001",
        "Virtualization/Sandbox Evasion: System Checks",
        "medium",
    ),
    (
        "virtualbox",
        "antivm:virtualbox",
        "T1497.001",
        "Virtualization/Sandbox Evasion: System Checks",
        "medium",
    ),
    (
        "vboxservice",
        "antivm:vboxservice",
        "T1497.001",
        "Virtualization/Sandbox Evasion: System Checks",
        "medium",
    ),
    (
        "vmtoolsd",
        "antivm:vmtoolsd",
        "T1497.001",
        "Virtualization/Sandbox Evasion: System Checks",
        "medium",
    ),
    (
        "qemu",
        "antivm:qemu",
        "T1497.001",
        "Virtualization/Sandbox Evasion: System Checks",
        "low",
    ),
    (
        "sandboxie",
        "antivm:sandboxie",
        "T1497.001",
        "Virtualization/Sandbox Evasion: System Checks",
        "medium",
    ),
];

/// `source_url` for the ATT&CK reference data.
pub const ATTACK_SOURCE_URL: &str = "https://attack.mitre.org/techniques/";
