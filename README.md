# pwn-pulse.sh
**Exploit for Pulse Connect Secure SSL VPN arbitrary file read vulnerability (CVE-2019-11510)**

Script authored by braindead @BishopFox. Based on [research by Orange Tsai and Meh Chang](https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html). Thanks also to Alyssa Herrera and 0xDezzy for additional insights

This script extracts private keys, usernames, admin details (including session cookies) and observed logins (including passwords) from Pulse Connect Secure VPN files downloaded via CVE-2019-11510.

* It takes the target domain or IP as an argument and will download important files from the server using the arbitrary file read vulnerability.
* It then greps through the files for sensitive information and dumps it all into a file named [TARGET]_extractions.txt
* By default, it will also test each session cookie to see if the session is currently active (and thus available for hijacking).

Additional details about the development of the script are available in [this blog article](https://know.bishopfox.com/blog/breaching-the-trusted-perimeter).

### Usage:
```
Download files, extract, and test:
   ./pwn-pulse.sh [TARGET DOMAIN/IP]
Extract from existing files only:
   ./pwn-pulse.sh --no-downloads [TARGET DOMAIN/IP]
Skip active session cookie tests:
   ./pwn-pulse.sh --no-cookie-tests [TARGET DOMAIN/IP]
```
