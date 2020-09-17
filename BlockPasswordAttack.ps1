#
# RDP\windows account attack automatic blocking script.
# 
# Script checks for failed authentication events in the security eventlog.
# Ensure failed logon attempts (ID 4625) are logged!
#
# The script will check for multiple failed logons (10) from a given IP.
# It does not care about the username used. Protects better towards password sprays, credential stuffing and brute force attacks.
#
# You will need whosip.exe if you would like to know subnet country info for the ip adress.
#  https://www.nirsoft.net/utils/whosip.html, place it in the windows folder
#
# Logging is written to: RDPFWlogging.txt
#
# ---------------------------------------------------------------------------------------------------
# (C)2020 Roeland Kluit
#
# The following is the disclaimer that applies to all scripts, functions, one-liners, etc. 
# You running this script/function means you will not blame the author(s) if this breaks your stuff.
# This script/function is provided AS IS without warranty of any kind.
# Author(s) disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
# The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
# In no event shall author(s) be held liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the script or documentation.
# Neither this script/function, nor any part of it other than those parts that are explicitly copied from others, may be republished or redistributed without author(s) express written permission.
# Author(s) retain the right to alter this disclaimer at any time. 
#
# ---------------------------------------------------------------------------------------------------
#
# Script version 1.2 - September 2020
#

##--Functions--

#
# Get country information for ip address
#
function Get-Whois ($ip)
{
    $result = New-Object PSObject
    cd $env:windir
    .\whosip.exe $ip | where { $_ -match "(.+?): *(.+)" } | foreach { $result | Add-Member noteProperty ($matches[1] -replace " ") $matches[2] } -ErrorAction Stop
    $result
}

#
# Add rule to existing filewall entry
#
function AddRule($iprange, $firewallrulename)
{
    try
    {
        $rule = Get-NetFirewallRule -DisplayName $firewallrulename -ErrorAction Stop
        $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
    }
    catch
    {
        "Cannot find or access Firewall rule: $_"
        return
    }


    $WhoisIf = "Unkown"
    try
    {
        $ipInfo  = Get-Whois $iprange
        $WhoisIf = "$($ipInfo.OwnerName) - $($ipInfo.Country)"
    }
    catch
    {}

    foreach($remip in $addressFilter.RemoteIP)
    {
            if($remip.StartsWith($iprange))
            {

                "Firewall is blocking IP-range: $($iprange) - `($($WhoisIf)`)"
                return
            }
    }

    "Adding block for $($range) - `($($WhoisIf)`)"
    [string[]] $ipaddrCollection = $addressFilter.RemoteIP
    $ipaddrCollection += "$iprange/255.255.255.0"

    $addressFilter | Set-NetFirewallAddressFilter -RemoteAddress $ipaddrCollection -ErrorAction Stop

}

function Block-BruteForceAttempts
{
    param(

        [Parameter(Mandatory = $True)]
        [int]$HowManyHoursBack,
        [Parameter(Mandatory = $True)]
        [string]$FirewallRuleName
    )

    "Starting check for Brute-Force RDP \ NetworkAuthentication Attempts within the last $HowManyHoursBack hours"
    $events = Get-EventLog -LogName "Security" -EntryType FailureAudit -InstanceId 4625 -After ([DateTime]::Now).AddHours((-1 * $HowManyHoursBack)) -ErrorAction Stop
    $ipList = @{}

    foreach($event in $events)
    {

        $ip = $event.ReplacementStrings[19]

        if($ipList.ContainsKey($ip))
        {
            $ipList[$ip] =  $ipList[$ip] + 1
        }
        else
        {
            $ipList.Add($ip, 1)
        }
    }

    foreach($ip in $ipList.Keys)
    {
        if($ipList[$ip] -ge 10) # add to list if failed 10 times
        {
            $range = ([IPAddress] (([IPAddress] "$ip").Address -band ([IPAddress] "255.255.255.0").Address)).ToString()
            if($range.StartsWith("172.16."))
            {
                "Internal IP Range: $range, Skipping"
            }
            elseif($range.StartsWith("10."))
            {
                "Internal IP Range: $range, Skipping"
            }
            elseif($range.StartsWith("fe80::"))
            {
                "Internal IPv6 Range: $range, Skipping"
            }
            elseif($range.StartsWith("192.168."))
            {
                "Internal IP Range: $range, Skipping"
            }
            elseif($range.StartsWith("127."))
            {
                "Loopback range: $range, Skipping"
            }
            elseif($range.Equals("::"))
            {
                "Loopback range: $range, Skipping"
            }
            else
            {            
                AddRule $range $FirewallRuleName
            }
        }
    }
}

#
# Create base firewall rule, if not exist
#
function CreateFirewallruleIfNotExist($name)
{
    try
    {
        $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction Stop
        $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
    }
    catch
    {
        "Cannot find Firewall rule, creating new."
        $prof = New-NetFirewallRule -DisplayName $name -Action Block -Direction Inbound -Enabled True -Profile Any -Description "This rule blocks any access to this machine after a couple of invalid logon attempts from this IP range, you can remove individual IPs. Ensure to have at least 1 IP in the remote adressed. Otherwise you will be locked out of your machine!"
        $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $prof -ErrorAction Stop
        $addressFilter | Set-NetFirewallAddressFilter -RemoteAddress "45.141.84.0" -ErrorAction Stop     # list must have at lease 1 ip adress, otherwise *ALL* inbound traffic is blocked
    }    
}

##--Main--

"$([DateTime]::Now) - Script started" | Out-File "RDPFWlogging.txt" -Append
CreateFirewallruleIfNotExist "Block Password Attack Attempts" | Out-File "RDPFWlogging.txt" -Append
Block-BruteForceAttempts 24 "Block Password Attack Attempts" | Out-File "RDPFWlogging.txt" -Append
"$([DateTime]::Now) - Script finished" | Out-File "RDPFWlogging.txt" -Append

##--End--
