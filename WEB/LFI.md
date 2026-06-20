# LFI
## Overview
[Good resourcee](https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html)
Local File Inclusion (LFI) occurs when an application loads or processes files using user-controlled input without proper validation. This can allow an attacker to access unintended files on the server.
LFI is commonly associated with dynamic file-loading functionality such as templates, language files, configuration files, and page routing systems.

LFI is a web application vulnerability that allows an attacker to access files stored on the server

example.com/index.php?page=etc/password

You can move up directories with ../../../../ -> example.com/index.php?page=./../../../etc/password

.. = parent directory

/ = directory separator

%00 = is a null byte, a special character that tells a computer, Stop reading here.

# PAYLOADS
[PAYLOADS](https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt)

-  example.com/index.php?page=./../../../etc/password
-  example.com/index.php?page=..%2f/etc/passwd
-  example.com/index.php?page=..%c0%af/etc/passwd
