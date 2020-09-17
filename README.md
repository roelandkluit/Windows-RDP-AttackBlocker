# Windows-RDP-AttackBlocker
RDP and windows account attack automatic blocking script.

Uses windows Firewall to block ip adresses that are authenticating and failing at least 10 times in the last 24 hours.

Script checks for failed authentication events in the security eventlog.
Ensure failed logon attempts (ID 4625) are logged!

The script will check for multiple failed logons (10) from a given IP.
It does not care about the username used. Protects better towards password sprays, credential stuffing and brute force attacks.

You will need whosip.exe if you would like to know subnet country info for the ip adress.
 https://www.nirsoft.net/utils/whosip.html, place it in the windows folder

Logging is written to: RDPFWlogging.txt

---------------------------------------------------------------------------------------------------
(C)2020 Roeland Kluit

The following is the disclaimer that applies to all scripts, functions, one-liners, etc. 
You running this script/function means you will not blame the author(s) if this breaks your stuff.
This script/function is provided AS IS without warranty of any kind.
Author(s) disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall author(s) be held liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the script or documentation.
Neither this script/function, nor any part of it other than those parts that are explicitly copied from others, may be republished or redistributed without author(s) express written permission.
Author(s) retain the right to alter this disclaimer at any time. 

---------------------------------------------------------------------------------------------------

Script version 1.2 - September 2020

Precondition
* Windows 2012 or later OS
* Powershell v5
* Windows build-in Firewall must de enabled

Installation

* Copy Script and whosip.exe to C:\Windows
* Import scheduled tasks XML (Import scheduled task in Task Scheduler)
* Ensure authentication failures are logged to the event log, and the log is sufficiently large to have a history of at least 24 hours (more=better)!
