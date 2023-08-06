---
title: "DarkGate - Threat Breakdown Journey"
classes: wide
header:
  teaser: /assets/images/DarkGate-Campaign-Analysis/logo.png
  overlay_image: /assets/images/DarkGate-Campaign-Analysis/logo.png
  overlay_filter: 0.5
ribbon: DarkSlateBlue
excerpt: "Shining a Light on the Hidden Tactics and Techniques Employed by DarkGate"
description: "Shining a Light on the Hidden Tactics and Techniques Employed by DarkGate"
categories:
  - Threat Breakdown
tags:
  - DarkGate
  - Loader
  - ShellCode
  - Delphi
  - Yara
  - IDA
  - IDAPython
  - Injection
toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
---
# Intro

Over the past month, a widespread phishing campaign has targeted individuals globally.

The campaigns execution chain ends with the deployment of a malware known as: DarkGate. A loader type malware.

DarkGate is exclusively sold on underground online forums and the developer keeps a very tight amount of seats for customers.

# The Lure

The adversary behind the campaign distributed a high volume campaign of phishing emails, those mails were stolen conversation threads that the adversary had access to.

The challenge here lies in the fact that users often trust what they remember, and because of that, I think users who aren't aware of such tactics could easily become infected and fall prey to the "social engineering" trap.

Below, you'll find an example of the content the adversary added to the hijacked conversation thread:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/1.png)

I’ve created a diagram that demonstrates the execution flow of the campaign:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/2.png)

# Geofence Check

To be honest, I still can’t tell what are the requirements to pass the checks conducted by the adversary, I’ve checked some of the URL’s in URLscan.io and found out that the ones that managed to retrieve a payload had the `refresh` header in the response (which makes sense) , the header contained the URL to the payload download, for example:

Honestly, I'm still trying to figure out what checks need to be passed to get through the geofence set by the adversary. After examining some of the URLs on URLscan.io, I discovered that those which were successful in obtaining a payload featured the `refresh` header in their response (makes sense). This header included the URL needed to download the payload, for instance:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/3.png)

If the user successfully passes the check, an MSI file is downloaded from the URL, following the structure: `Project_[0-9]{7}\.msi`

# MSI Loader

The downloaded MSI carries two embedded files:

- CustomAction.dll
- WrappedSetupProgram.cab

The DLL is called upon by the MSI to unpack the content housed in WrappedSetupProgram.cab and execute it.

The cab archive includes two files:

- Autoit3.exe
- UGtZgHHT.au3 (AutoIT 3 script)

![Untitled](/assets/images/DarkGate-Campaign-Analysis/4.png)

# AutoIT Script

## Extracting The Script

Upon initial examination, the script appears to be altered. Typically, most AutoIT scripts I've come across begin with the magic bytes `A3 48 4B BE` and `41 55 33 21 45 41` (AU3!EA) like explained in this [blog](https://ghoulsec.medium.com/mal-series-6-autoit-analysis-guide-30072dda044a):

> *You can find the au3 script magic `bytes AU!EA06`(06 here is the subtype of the script), inside of its hex dump as shown in the picture below.*
> 

![Untitled](/assets/images/DarkGate-Campaign-Analysis/5.png)

However, the script I analyzed contained a substantial amount of what seemed to be junk data at the start of the file. (We'll get back to this later in the blog)

I managed to locate the magic bytes indicating the AU3 script's starting point at the offset `0xA0A5C`:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/6.png)

To extract the actual script, I changed the file's extension from au3 to a3x (representing an AutoIT3 compiled script) and used the tool [myAut2Exe](https://github.com/fossabot/myAut2Exe) for extraction.

## Shellcode CallWindowProc Injection

The AU3 script consists of two main components:

1. A segmented hex-encoded shellcode that is concatenated into a single variable.
2. Injection and execution of the shellcode.

The first part is quite self-explanatory. In my analysis, the variable was named **$SSUGZNUOOE**, and it appeared over 2,000 times in the script:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/7.png)

The second segment of the script initiates by verifying the existence of the ProgramFiles folder and confirming that the username executing the script is not **SYSTEM**. I suspect these checks are evasion tactics to ensure the script runs within a standard Windows environment rather than a sandbox or custom setup.

The script proceeds to convert the hex-encoded shellcode to a binary string using the `BinaryToString` function and assigns it to the **$MZRSVIMCSW** variable. The variable **$MFCKUCOYGW** is initialized as a DLL structure sized to the shellcode using the `DllStructCreate` function.

The script checks if the path `C:\Program Files (x86)\Sophos` exists. If it doesn't, a hex-encoded command is executed which, upon decoding, reveals the use of the API `VirtualProtect` to modify the memory region protection of $MZRSVIMCSW to ERX. (My theory is that the DarkGate developer noticed Sophos could detect changes in protection type)

The script then copies the content of the shellcode into the DLL structure and injects it by calling the API `CallWindowProc`. (I found a [youtube video](https://www.youtube.com/watch?v=tBDolrwd79M) that presents a POC for the injection) 

![Untitled](/assets/images/DarkGate-Campaign-Analysis/8.png)

## ShellCode Analysis

Upon loading the ShellCode in IDA, it becomes immediately apparent that the shellcode consists of a single large function that loads stack-strings.

![Untitled](/assets/images/DarkGate-Campaign-Analysis/9.png)

In addition, I used [FLOSS](https://github.com/mandiant/flare-floss) to check on the strings and FLOSS successfully extracted 71 strings:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/10.png)

Next, I will use [BlobRunner](https://github.com/OALabs/BlobRunner) to invoke the shellcode, set a breakpoint after all the stack-strings have been pushed onto the stack, and dump the memory containing the executable that was pushed:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/11.png)

# Loader Analysis

The loader we’ve dumped will be in charge of decoding and executing part of the junk data stored inside of the AutoIT script (After decoding we will face with the final binary which is the ***DarkGate*** loader)

The loader requires a a command line argument which will be the path to the AutoIT script. The loader will check for the argument and if it’s not ends with ********.au3******** or the executable can’t get a handle for the file a message box with the text “******bin 404******” will appear and the loader will terminate itself.

![Untitled](/assets/images/DarkGate-Campaign-Analysis/12.png)

When the loader successfully accesses the AutoIT script, it reads its content and segments it based on the character: **`|`** (0x7C).

Next, the loader retrieves 8 bytes from the second offset of the data located in the second element of the array. (Represented as: `stringsArray[2][1:9] == xorKeyData`).

The character `a` is then prefixed to these extracted bytes. (Resulting in: `a + xorKeyData == modifiedXorKey`).

To generate the decryption key, the loader first determines the length of the concatenated byte array, then employs an XOR loop over each byte in the array (`len(modifiedXorKey) ^ modifiedXorKey[0] ^ modifiedXorKey[1] ...`).

The loader fetches the data from the third element of the array and decodes it from base64. Each byte of this data is XOR-ed with the decryption key and also applied with a NOT operation.

![Untitled](/assets/images/DarkGate-Campaign-Analysis/13.png)

The outcome of this process is an executable, which is the final payload (**DarkGate** malware)

![Untitled](/assets/images/DarkGate-Campaign-Analysis/14.png)

To streamline this process, I've created a Python script capable of extracting and decrypting the DarkGate payload from the AutoIT script:

```python
from base64 import b64decode

AUTO_IT_PATH = '' #Change to the AutoIT script path.
FINAL_PAYLOAD_PATH = '' #Change to output path.

fileData = open(AUTO_IT_PATH, 'rb').read().decode(errors='ignore')

stringsArray = fileData.split('|')
modifiedXorKey = 'a' + stringsArray[1][1:9]

decodedData = b64decode(stringsArray[2])
key = len(modifiedXorKey)

for byte in modifiedXorKey:
    key ^= ord(byte)

finalPayload = b''

for byte in decodedData:
    finalPayload += bytes([~(byte ^ key)& 0xFF])

open(FINAL_PAYLOAD_PATH, 'wb').write(finalPayload)
print('[+] Final Payload Was Created!')
```

# DarkGate Analysis

Essentially, you can read through the developer's sale thread on [xss.is](https://xss.is/threads/90634/) and understand the various capabilities of the loader, which include:

- HVNC
- Crypto miner setup
- Browser history and cookie theft
- RDP
- HAnyDesk

![Untitled](/assets/images/DarkGate-Campaign-Analysis/15.png)

During my analysis, my primary objective was to decrypt the contained strings, locate the C2 strings (since they're not available in plain text), and decrypt the network traffic.

## Strings Decryption

During my investigation, I found two embedded strings (each 64 characters long) which are invoked by two different but similar functions:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/16.png)

When checking the cross-references for the first string (used in the function on the left), we can see a total of **864** calls to the function.

![Untitled](/assets/images/DarkGate-Campaign-Analysis/17.png)

The first argument passed to the function is the container for the return value, and the second argument is the "encrypted" string.

These hard-coded strings are part of a custom Base64 decoding routine. I'd like to extend my personal thanks to [@rivitna2](https://twitter.com/rivitna2) for correcting me when initially published the strings decoding script.

[https://twitter.com/rivitna2/status/1686309211163021312?ref_src=twsrc%5Etfw">August](https://twitter.com/rivitna2/status/1686309211163021312?ref_src=twsrc%5Etfw">August)

The first batch of decoded strings represents all the strings utilized by DarkGate during its execution. Some of these strings looks like notification messages sent to the C2, such as:

```
- New Bot: DarkGate is inside hAnyDesk user with admin rights
- DarkGate not found to get executed on the new hAnyDesk Desktop, Did you enabled Startup option on builder?
- Credentials detected, removing them!
```

You can find a list of all decoded strings [here](https://gist.github.com/0xToxin/b9b1db86f8b395a6ef6c6e99698d1f64)

The second hard-coded string is employed in the same routine, but it's called much less frequently. The developer tried to mess up a bit with researchers from discovering DarkGate's configurations by adding this second hard-coded string. It is used for decoding DarkGate's configurations and it also plays a role in decoding the network traffic data.

By decoding the data associated with the second hard-coded string, I managed to uncover DarkGate's configuration:

```
http://80.66.88.145|
0=7891
1=Yes
2=Yes
3=No
5=Yes
4=50
6=No
8=Yes
7=4096
9=No
10=bbbGcB
11=No
12=No
13=Yes
14=4
15=bIWRRCGvGiXOga
16=4
17=No
18=Yes
19=Yes
```

Below is an IDAPython script that requires both the wrapper function calls and the hard-coded strings:

```python
import idc
import idautils
import idaapi
import re

DECRYPTION_FUNCTION_1 = # Replace with "Wrapper" function call
LIST_1 = # Add 64 length list 
STRINGS_FILE_1 = # Output file path

DECRYPTION_FUNCTION_2 = # Replace with "Wrapper" function call
LIST_2 = # Add 64 length list 
STRINGS_FILE_2 = # Output file path

def decShiftFunc(arg1, arg2, arg3, arg4):
    final = ''
    tmp = (arg1 & 0x3F) * 4
    final += chr(((arg2 & 0x30) >> 4) + tmp)
    tmp = (arg2 & 0xF) * 16
    final += chr(((arg3 & 0x3C) >> 2) + tmp)
    final += chr((arg4 & 0x3F) + ((arg3 & 0x03) << 6))
    return final.replace('\0','')

def decWrapperFunc(encData, listNum):
    hexList = []
    for x in encData:
        hexList.append(listNum.index(x))

    subLists = [hexList[i:i+4] for i in range(0, len(hexList), 4)]
    if len(subLists[-1]) < 4:
        subLists[-1].extend([0x00] * (4 - len(subLists[-1])))

    finalString = ''
    for subList in subLists:
        finalString += decShiftFunc(subList[0],subList[1],subList[2],subList[3])
    return finalString

def getArg(ref_addr):
    ref_addr = idc.prev_head(ref_addr)
    if idc.print_insn_mnem(ref_addr) == 'mov':
        if idc.get_operand_type(ref_addr, 1) == idc.o_imm:
            return(idc.get_operand_value(ref_addr, 1))
        else:
            return None

def listDecrypt(functionEA, listID, fileID):
    stringsList = []
    for xref in idautils.XrefsTo(functionEA):
        argPtr = getArg(xref.frm)
        if not argPtr:
            continue
        data = idc.get_bytes(argPtr, 300)
        encData = re.sub(b'[^\x20-\x7F]+', '', data.split(b'\x00')[0]).decode() # Cleaning...
        decData = decWrapperFunc(encData,listID)
        stringsList.append(decData)
        idc.set_cmt(idc.prev_head(xref.frm), decData, 1)
    
    print(f'[+] {len(stringsList)} Strings were extracted')
    out = open(fileID, 'w')
    for string in stringsList:
        out.write(f'{string}\n')
    out.close()

print('[*] Staring decryption of list 1')
listDecrypt(DECRYPTION_FUNCTION_1,LIST_1,STRINGS_FILE_1)
print('[+] Staring decryption of list 2')
listDecrypt(DECRYPTION_FUNCTION_2,LIST_2,STRINGS_FILE_2) 
```

## Network Traffic Decryption

As I hinted in the previous section, DarkGate's network activity indeed incorporates both data obfuscation techniques we've encountered during the analysis:

- Loop XOR
- Custom Base64 Decoding

Now, let's examine one of the network streams that is transmitted to the C2:

![Untitled](/assets/images/DarkGate-Campaign-Analysis/18.png)

In the POST request, we can observe several fields:

- id
- data
- act

The **id** is our XOR key initializer, which generates the actual XOR key using the same technique we used to initialize the XOR key for decrypting the final DarkGate payload. (`len(id) ^ id[0] ^ id[1] ..`) 

The **data** field is encoded using the second hard-coded string. After decoding, this string will undergo an XOR operation with the key generated from **id**, as well as a NOT operation.

To simplify this process, I've created a Python script that decrypts the data:

```python
LIST = '' # Replace list used for config decoding
DATA = '' # Replace with the encrypted data from the network traffic
ID = '' # Replace with the ID from the network traffic

def decShiftFunc(arg1, arg2, arg3, arg4):
    final = ''
    tmp = (arg1 & 0x3F) * 4
    final += chr(((arg2 & 0x30) >> 4) + tmp)
    tmp = (arg2 & 0xF) * 16
    final += chr(((arg3 & 0x3C) >> 2) + tmp)
    final += chr((arg4 & 0x3F) + ((arg3 & 0x03) << 6))
    return final.replace('\0','')

hexList = []
for x in DATA:
    hexList.append(LIST.index(x))

subLists = [hexList[i:i+4] for i in range(0, len(hexList), 4)]
if len(subLists[-1]) < 4:
    subLists[-1].extend([0x00] * (4 - len(subLists[-1])))

finalString = ''
for subList in subLists:
    finalString += decShiftFunc(subList[0],subList[1],subList[2],subList[3])

key = len(ID)

for x in ID:
    key ^= ord(x)

plainData = ''
for x in finalString:
    plainData += chr(~(ord(x) ^ key)& 0xFF) 

print(f'[+] Output: {plainData}')
```

Below is the output of the script for these parameters:

- LIST = **zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT**+=
- DATA = **FpOkFahzFpOuNjxuFsfNFsOAMpOuNvkuFQrcHwtMDfmlHahzFpOuNqOuFs7uFsOAJqOuNj5uFs3kFsOAFpOuNqxuFs3WFsOAjjOuNvkuFsSuFsOLNjOuNjkuFs70FsOAMpOuNj3uFs3WFsOANpOuNqSuFsSuFsOxMsOuFq3uFsYzFsO0FsOuNskuFs7sFsOxNsOuNjkuFs70FsOAjpOuNjyuFsf5FsO0FsOuNpOuFs3UFsOAFqOuNvSuFs3UFsOANqOuNjkuFsSuFsO0jsOuFjOuFskLFsOzjpOuNpSuFsxLFsOzNqOuNs5uFskkFsOLNsOuNskuFsk0FsOzNpOuNsxuFsSuFsO0jsOuFjOuFskxFsOxFjOuNjyuFs7uFsOxFsOuNjkuFs3zFsO0FsOuNqkuFs7kFsOAMpOuNvkuFs3xFsO0FsOuN3xuFskkFsOzMpOuFjOuFskxFsOxFjOuNjyuFs7uFsOxFsOuNjkuFs70FsO0FsOuNj3uFs70FsOAjjOuNvxuFsSuFsOxNqOuNq7uFs7xFsO0jpOuNjkuFs7sFsOANpOuNvxuFs7kFsOAMpOuFvkuFs3kFsOAjjOuNvxuFQh0NsOAMsmQB9nzl9h2JcD0lVRl6HDylgok4aS253G04cmeCc0g4W52JWOs13oS6H0krsANFsOAMpOuNjYuFs70FsOAjjOuNqYuFsftFsOANjOuNqxuFsSuFsOzFjOuNjyuFs7kFsOAMpOuNjYuFsSuFsOzNsOuNj5uFs7kFsOxFsOuNvYuFs3UFsOxMpOuFjOuFsxUFsOANsOuNjyuFs7uFsOxNsOuNjkuFs70FsRQMsyWFJRcJZrh89ne4aEk1syu1fR04TO2hs3z13GL89re1syWFsxUrfIP6arQFp3WFsxzNpYLFar64HBG4aEGrsxGNZhursRQNqMWFe**
- ID = **GEabbfEcbKBadGaccCDCaGKccGGfKHKG**

```
1033|410064006D0069006E00|MSXGLQPS|4100700070006C00690063006100740069006F006E0020005600650072006900660069006500720020007800360034002000450078007400650072006E0061006C0020005000610063006B0061006700650020002D00200055004E00520045004700490053005400450052004500440020002D002000570072006100700070006500640020007500730069006E00670020004D0053004900200057007200610070007000650072002000660072006F006D0020007700770077002E006500780065006D00730069002E0063006F006D00|240681|Intel Core Processor (Broadwell) @ 8 Cores|4D006900630072006F0073006F0066007400200042006100730069006300200044006900730070006C006100790020004100640061007000740065007200|8192 MB|Windows 10 Pro  x64 Build 19041|Yes||1690445353|Uno.own|4.6|0|0|7891
```

# Summary

On this campaign we’ve uncovered a global campaign using hijacked email threads for phishing, which leads to the download of a sophisticated malware known as DarkGate. Users downloading the malware received an MSI file with two embedded files which carried encoded shellcode for execution. DarkGate also used unique decoding for two embedded strings, revealing commands sent to the C2 and the malware's configuration. Obfuscation techniques like Loop XOR and custom Base64 decoding were observed in DarkGate's network activity. Python scripts were created to decrypt the payload and data in this comprehensive analysis.

# Yara Rule

I created a YARA rule based on the procedure used to decode the strings:

```makefile
rule Win_DarkGate
{
	meta:
		author = "0xToxin"
		description = "DarkGate Strings Decoding Routine"
		date = "2023-08-01"
	strings:
		$chunk_1 = {
			8B 55 ??
			8A 4D ??
			80 E1 3F
			C1 E1 02
			8A 5D ??
			80 E3 30
			81 E3 FF 00 00 00
			C1 EB 04
			02 CB
			88 4C 10 ??
			FF 45 ??
			80 7D ?? 40
			74 ??
			8B 45 ??
			E8 ?? ?? ?? ??
			8B 55 ??
			8A 4D ??
			80 E1 0F
			C1 E1 04
			8A 5D ??
			80 E3 3C
			81 E3 FF 00 00 00
			C1 EB 02
			02 CB
			88 4C 10 ??
			FF 45 ??
			80 7D ?? 40
			74 ??
			8B 45 ??
			E8 ?? ?? ?? ??
			8B 55 ??
			8A 4D ??
			80 E1 03
			C1 E1 06
			8A 5D ??
			80 E3 3F
			02 CB
			88 4C 10 ??
			FF 45 ??
		}
	
	condition:
		any of them
}
```

# References

- [DarkGate Final Payload Extractor](https://gist.github.com/0xToxin/43e25700510ad3cc6268994b56c9a710)
- [DarkGate Strings Decoder](https://gist.github.com/0xToxin/c85c23b99d04fbb27bb4d5160f4b86a6)
- [DarkGate Decoded Strings](https://gist.github.com/0xToxin/b9b1db86f8b395a6ef6c6e99698d1f64)
- [DarkGate Network Traffic Decryptor](https://gist.github.com/0xToxin/64c007101f4ec3efc2f9b2e37b449899)
- [Fortinet Blog About DarkGate](https://www.fortinet.com/blog/threat-research/enter-the-darkgate-new-cryptocurrency-mining-and-ransomware-campaign)
- [DarkGate Selling Thread On xss.is](https://xss.is/threads/90634/)
- [Triage Scan](https://tria.ge/230727-j1rfxscg7s/behavioral2)