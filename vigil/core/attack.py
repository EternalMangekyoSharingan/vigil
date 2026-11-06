"""MITRE ATT&CK tags for Vigil's checks.

Each finding gets the techniques its check is evidence of, so findings from different
tools speak one vocabulary: Cases orders a storyline by tactic, the STIX export carries
attack-pattern objects, and an AI assistant can reason in the terms analysts use.

The mapping is Vigil's own judgement of which technique a check is evidence *for*; it
says "this looks like", never "this is". Names follow attack.mitre.org (Enterprise).
"""

import re

URL = "https://attack.mitre.org/techniques/{}/"
TACTICS = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
           "credential-access", "discovery", "lateral-movement", "collection", "command-and-control",
           "exfiltration", "impact"]
TACTIC_NAMES = {t: t.replace("-", " ").title().replace("And", "and") for t in TACTICS}

TECHNIQUES = {
    "T1195.001": ("Compromise Software Dependencies and Development Tools", "initial-access"),
    "T1195.002": ("Compromise Software Supply Chain", "initial-access"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1203": ("Exploitation for Client Execution", "execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "execution"),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", "execution"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "execution"),
    "T1559.002": ("Inter-Process Communication: Dynamic Data Exchange", "execution"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "persistence"),
    "T1053.006": ("Scheduled Task/Job: Systemd Timers", "persistence"),
    "T1547.006": ("Boot or Logon Autostart Execution: Kernel Modules and Extensions", "persistence"),
    "T1547.013": ("Boot or Logon Autostart Execution: XDG Autostart Entries", "persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification", "persistence"),
    "T1546.016": ("Event Triggered Execution: Installer Packages", "persistence"),
    "T1546.017": ("Event Triggered Execution: Udev Rules", "persistence"),
    "T1037.004": ("Boot or Logon Initialization Scripts: RC Scripts", "persistence"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "persistence"),
    "T1136.001": ("Create Account: Local Account", "persistence"),
    "T1505.003": ("Server Software Component: Web Shell", "persistence"),
    "T1556.003": ("Modify Authentication Process: Pluggable Authentication Modules", "credential-access"),
    "T1574.006": ("Hijack Execution Flow: Dynamic Linker Hijacking", "persistence"),
    "T1548.001": ("Abuse Elevation Control Mechanism: Setuid and Setgid", "privilege-escalation"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "privilege-escalation"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "credential-access"),
    "T1552.004": ("Unsecured Credentials: Private Keys", "credential-access"),
    "T1555": ("Credentials from Password Stores", "credential-access"),
    "T1555.003": ("Credentials from Password Stores: Credentials from Web Browsers", "credential-access"),
    "T1555.005": ("Credentials from Password Stores: Password Managers", "credential-access"),
    "T1539": ("Steal Web Session Cookie", "credential-access"),
    "T1528": ("Steal Application Access Token", "credential-access"),
    "T1005": ("Data from Local System", "collection"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1027.006": ("Obfuscated Files or Information: HTML Smuggling", "defense-evasion"),
    "T1027.009": ("Obfuscated Files or Information: Embedded Payloads", "defense-evasion"),
    "T1027.013": ("Obfuscated Files or Information: Encrypted/Encoded File", "defense-evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "defense-evasion"),
    "T1036.002": ("Masquerading: Right-to-Left Override", "defense-evasion"),
    "T1036.004": ("Masquerading: Masquerade Task or Service", "defense-evasion"),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", "defense-evasion"),
    "T1036.007": ("Masquerading: Double File Extension", "defense-evasion"),
    "T1036.008": ("Masquerading: Masquerade File Type", "defense-evasion"),
    "T1070.004": ("Indicator Removal: File Deletion", "defense-evasion"),
    "T1218": ("System Binary Proxy Execution", "defense-evasion"),
    "T1221": ("Template Injection", "defense-evasion"),
    "T1222.002": ("File and Directory Permissions Modification: Linux and Mac", "defense-evasion"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "defense-evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "defense-evasion"),
    "T1564.001": ("Hide Artifacts: Hidden Files and Directories", "defense-evasion"),
    "T1564.003": ("Hide Artifacts: Hidden Window", "defense-evasion"),
    "T1620": ("Reflective Code Loading", "defense-evasion"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "command-and-control"),
    "T1095": ("Non-Application Layer Protocol", "command-and-control"),
    "T1102": ("Web Service", "command-and-control"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1571": ("Non-Standard Port", "command-and-control"),
    "T1029": ("Scheduled Transfer", "exfiltration"),
}

BY_CHECK = {
    # Vigil Pkg
    ("pkg", "known_malicious"): ["T1195.002"],
    ("pkg", "known_hijacked"): ["T1195.002"],
    ("pkg", "lookalike_name"): ["T1195.002", "T1036.005"],
    ("pkg", "installed_known_malicious"): ["T1195.002"],
    ("pkg", "installed_hijack_window"): ["T1195.002"],
    ("pkg", "installed_lookalike"): ["T1195.002", "T1036.005"],
    ("pkg", "source_raw_ip"): ["T1105"], ("pkg", "source_pastebin"): ["T1105", "T1102"],
    ("pkg", "source_shortener"): ["T1105"], ("pkg", "source_file_host"): ["T1105", "T1102"],
    ("pkg", "checksum_skip"): ["T1195.002"], ("pkg", "network_in_build"): ["T1105"],
    ("pkg", "registry_in_build"): ["T1195.001"], ("pkg", "pipe_to_shell"): ["T1059.004", "T1105"],
    ("pkg", "run_substitution"): ["T1059.004", "T1105"], ("pkg", "dev_tcp"): ["T1059.004", "T1095"],
    ("pkg", "decode_and_run"): ["T1140", "T1059.004"], ("pkg", "decode"): ["T1140"],
    ("pkg", "eval"): ["T1059.004", "T1027"], ("pkg", "encoded_blob"): ["T1027"],
    ("pkg", "download_to_tmp"): ["T1105"], ("pkg", "top_level_command"): ["T1059.004"],
    ("pkg", "top_level_substitution"): ["T1059.004"], ("pkg", "chmod_run"): ["T1222.002", "T1059.004"],
    ("pkg", "install_network"): ["T1546.016", "T1105"], ("pkg", "install_service"): ["T1546.016", "T1543.002"],
    ("pkg", "install_user_service"): ["T1543.002"], ("pkg", "user_service"): ["T1543.002"],
    ("pkg", "install_user_add"): ["T1136.001"], ("pkg", "install_privilege"): ["T1098"],
    ("pkg", "install_setuid"): ["T1548.001"], ("pkg", "install_cron"): ["T1053.003"],
    ("pkg", "security_off"): ["T1562.001", "T1562.004"], ("pkg", "sudo"): ["T1548.003"],
    ("pkg", "write_outside"): ["T1546.016"], ("pkg", "hook_network"): ["T1546.016", "T1105"],
    ("pkg", "desktop_command"): ["T1204.002"], ("pkg", "install_top_level"): ["T1546.016"],
    ("pkg", "new_maintainer"): ["T1195.002"], ("pkg", "aur_changed_hands"): ["T1195.002"],
    ("pkg", "aur_new_account"): ["T1195.002"], ("pkg", "srcinfo_mismatch"): ["T1195.002"],
    ("pkg", "folder_program"): ["T1195.002"],
    # Vigil Files
    ("files", "archive_setuid"): ["T1548.001"], ("files", "archive_encrypted"): ["T1027.013"],
    ("files", "inspector_disguise"): ["T1036.007", "T1036.002"], ("files", "inspector_type_mismatch"): ["T1036.008"],
    ("files", "inspector_macro_autoexec"): ["T1204.002", "T1059.005"], ("files", "inspector_macros"): ["T1059.005"],
    ("files", "inspector_macro_behaviour"): ["T1059.005", "T1105"], ("files", "inspector_xlm_macro"): ["T1204.002"],
    ("files", "inspector_remote_template"): ["T1221"], ("files", "inspector_remote_object"): ["T1221"],
    ("files", "inspector_dde"): ["T1559.002"], ("files", "inspector_embedded_object"): ["T1027.009"],
    ("files", "inspector_rtf_object"): ["T1027.009"], ("files", "inspector_encrypted"): ["T1027.013"],
    ("files", "inspector_pdf_javascript"): ["T1059.007", "T1204.002"], ("files", "inspector_pdf_autorun"): ["T1204.002"],
    ("files", "inspector_pdf_launch"): ["T1204.002"], ("files", "inspector_pdf_embedded"): ["T1027.009"],
    ("files", "inspector_pdf_obfuscation"): ["T1027"], ("files", "inspector_html_smuggling"): ["T1027.006"],
    ("files", "inspector_download_cradle"): ["T1059.001", "T1105"],
    ("files", "inspector_hidden_powershell"): ["T1059.001", "T1564.003"],
    ("files", "inspector_pipe_to_shell"): ["T1059.004", "T1105"], ("files", "inspector_reverse_shell"): ["T1059.004"],
    ("files", "inspector_lolbin"): ["T1218"], ("files", "inspector_temp_exec"): ["T1222.002"],
    ("files", "inspector_persistence"): ["T1053.003"], ("files", "downloads_program"): ["T1204.002"],
    ("files", "desktop_command"): ["T1204.002", "T1036.008"], ("files", "desktop_disguise"): ["T1036.008"],
    ("files", "desktop_download"): ["T1204.002"],
    # Vigil Tasks
    ("tasks", "memory_only"): ["T1620"], ("tasks", "deleted_binary"): ["T1070.004"],
    ("tasks", "hidden_binary"): ["T1564.001"], ("tasks", "ld_preload"): ["T1574.006"],
    ("tasks", "fake_kernel_name"): ["T1036.004"], ("tasks", "masquerade_name"): ["T1036.005"],
    ("tasks", "reverse_shell"): ["T1059.004"],
    # Vigil Persist (content checks are tagged per location in persist/scan.py)
    ("persist", "package_changed"): [],
}
# Persist: by location group (and kind, for timers and boot scripts).
BY_PERSIST_GROUP = {
    "systemd": ["T1543.002"], "cron": ["T1053.003"], "autostart": ["T1547.013"], "shell": ["T1546.004"],
    "preload": ["T1574.006"], "pam": ["T1556.003"], "sudoers": ["T1548.003"], "ssh": ["T1098.004"],
    "modules": ["T1547.006"], "udev": ["T1546.017"],
}
ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def tag(tid):
    name, tactic = TECHNIQUES.get(tid, (tid, None))
    return {"id": tid, "name": name, "tactic": tactic, "url": URL.format(tid.replace(".", "/"))}


def for_check(tool, check):
    return [tag(t) for t in BY_CHECK.get((tool, check), [])]


def for_persist(group, kind="", path=""):
    ids = list(BY_PERSIST_GROUP.get(group, []))
    if path.endswith(".timer"):
        ids = ["T1053.006"]
    if kind == "boot script":
        ids = ["T1037.004"]
    if kind == "package manager hook":
        ids = ["T1546.016"]
    return [tag(t) for t in ids]


def tactic_rank(t):
    return TACTICS.index(t["tactic"]) if t.get("tactic") in TACTICS else len(TACTICS)
