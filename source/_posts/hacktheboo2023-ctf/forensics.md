---
title: "Hacktheboo 2023 CTF"
date: 2023-10-23T17:21:14+03:00
draft: false
tags: ["ctf"]
ShowReadingTime: true
description: "Challenges Writeup"
ShowPostNavLinks: true
ShowToc: true
top_img: /images/cyberpunk-red.jpg
---

![](https://i.imgur.com/GMsEYt3.png)

Hi 👋, in this article i'll be sharing some challenges from the hacktheboo ctf challenges that was up i covered 3 challenges didn't touch on the rest that much. So for the first bat challenge it was under the practice section and the last two are forensics which i decided to work on they were interesting. 

Hope you have a nice read 😅


## Bat Problems

### Explanation
We are given the following file:
* `payload.bat`: Malicious bat file.

As we can see from the following image, the bat script contains many random variables that are assigned random values. In a batch script (a .bat or .cmd file), the set command defines and manipulates environment variables which store information that can be used by the script or other programs running in the same environment (the Command Prompt session).

![](https://i.imgur.com/6Ila1bK.png)

### Solution

First, the bat file can be analyzed using `Any.Run` which is a malware analyzer tool.
We will get the following result if we upload the sample on the aforementioned site.

![](https://i.imgur.com/qHgSgit.png)

By analyzing the behavior graph, we notice three actions made:
1. The attacker can be seen using `cmd` to copy PowerShell to a different path with a random name (Earttxmxaqr.png). 
1. The attacker then uses cmd again to rename the downloaded bat file and also change it's extension to `.png.bat` to avoid detection.
1. The attacker executes the base64 encoded string using the renamed PowerShell executable (`-enc` argument in Powershell is used to pass a base64 encoded command).

![](https://i.imgur.com/TnYjjwM.png)

By decoding the string, the flag can be retrieved.

![](https://i.imgur.com/yXGbDwO.png)

## Trick or Treat

### Explanation
We are given the following file:
* `capture.pcap`: Packet capture file
* `trick_or_treat.lnk`: The malicious file

Since the malicious file is provided by HTB, we can first gain additional information on it through `VirusTotal`, a famous OSINT website. After scanning, the file shows that it is indeed malicious and it connects to a malicious domain called `windowsliveupdater.com`. We also can notice that the file is connected to a few IP addresses, mainly `209.197.3.8` which is the malicious one.

![](https://i.imgur.com/2D3e9x9.png)

Analyzing further, we can understand what kind of processes are executed by the malicious file and how it attacks a system.

As shown in the picture below, the malicious file seems to download malicious data from `http://windowsliveupdater.com` using a random User-Agent for HTTP requests to essentially mask its identity on the network. It then sets the downloaded data into a variable (`$vurnwos`) and processes the characters in pairs and converts them from hexadecimal representation to their actual characters. It then performs a bitwise XOR operation with `0x1d` on each character and the output is appended to the `$vurnwos` string. Finally, it executes the variable using `Invoke-Command`. It also attempts to execute an empty variable (`$asvods`).

![](https://i.imgur.com/CCvPfrn.png)

After knowing what the malicious file does, the packet capture file can be analyzed using Wireshark to find the downloaded content. Since we know that the malicious file requested data from a website, we can filter `HTTP` packets only.

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/ctf4.png)

Going through the HTTP packets, we find a packet that shows the victim sending a GET request to `http://windowsliveupdater.com`. Analyzing the `User-Agent`, we can see that it is one of the randomized user agents set in the malicious file.

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/ctf5.png)

Now we know that that the IP address `77.74.198.52` is responsible for the malicious file execution, we can check its HTTP response. Notice that the HTTP response packet has a cleartext data that is truncated because it is too long for Wireshark. The data is our key to getting the flag and it must be extracted using the decoding method specified in the malicious file.

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/ctf6.png)

![](https://i.imgur.com/DcWJVAU.png)


### Solution
Since we know that the downloable content is encoded in hex and also XOR'ed using this key `0x1d`, we can use `CyberChef` to extract the content.

![](https://i.imgur.com/kk8AUa1.png)

## ValHalloween 

### Explanation
We are given the following file:
* `Logs`: Directory containing various Windows XML EventLog (.evtx) files

In this challenge, we are given a series of questions that must be answered to obtain the flag. These answers can all be located in certain event log files provided by HTB.

### Solution
1. What are the IP address and port of the server from which the malicious actors downloaded the ransomware? (for example: 98.76.54.32:443)
* Answer: `103.162.14.116:8888`

To complete this question, we can analyze the `Security` log file and filter the logs with event ID 4688 which is normally logged in Event Viewer when a new process is created. After filtering the results, we find a Powershell script that was executed to download the ransomware ('mscalc.exe') from a malicious server with its IP address and port. Additionally, we now know the estimated time of the ransomware attack is around 11:03:24 AM on 20/9/2023.

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win2.png)

2. According to the sysmon logs, what is the MD5 hash of the ransomware? (for example: 6ab0e507bcc2fad463959aa8be2d782f)
* Answer: `B94F3FF666D9781CB69088658CD53772`

To complete this question, we can analyze the `sysmon` log file and filter the logs with event ID 1 which is normally logged in Event Viewer when a new process is created. After filtering the results and since we know the Powershell script downloads the ransomware, we can attempt to find its child processes to locate the creation process of the ransomware. After analyzing the logs, we can find the ransomware with its MD5 hash.

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win3.png)

3. Based on the hash found, determine the family label of the ransomware in the wild from online reports such as Virus Total, Hybrid Analysis, etc. (for example: wannacry)
* Answer: `lokilocker`

To complete this question, just put the ransomware's MD5 hash to any OSINT tool and check its family labels.

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win4.png)

4. What is the name of the task scheduled by the ransomware? (for example: WindowsUpdater)
* Answer: `Loki`


To complete this question, we can analyze the `sysmon` log file and filter the logs with keyword 'schtasks' which is the name for task scheduling process. After filtering the results, we find a schtasks program with the parent process being the ransomware.

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win5.png)

5. What are the parent process name and ID of the ransomware process? (for example: svchost.exe_4953)
* Answer: `powershell.exe_3856`

To complete this question, we can analyze the `sysmon` log file and check the ransomware process again. Viewing the XML format of the ransomware process, we can easily find the parent process name and ID of the ransomware process.

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win6.png)

6. Following the PPID, provide the file path of the initial stage in the infection chain. (for example: D:\Data\KCorp\FirstStage.pdf)
* Answer: `C:\Users\HoaGay\Documents\Subjects\Unexpe.docx`

To complete this question, we can analyze the `Security` log file again and check the Powershell script process again. As the question suggests, we can use the PPID to retrace the steps to the initial stage in the infection chain. As shown in the pictures below, we then stumble upon a malicious `.docx` file

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win7.png)


![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win8.png)

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win9.png)

7. When was the first file in the infection chain opened (in UTC)? (for example: 1975-04-30_12:34:56)
* Answer: `2023-09-20_03:03:20`

To complete this question, we can just view the XML format of the `.docx` file and find the `TimeCreated SystemTime` row. ENSURE THE TIME FORMAT IS IN UTC!

![](https://github.com/warlocksmurf/hacktheboo2023-ctf/raw/main/images/win10.png)
