hosts discovery

for i in {1..255} ;do (ping -c 1 172.16.1.$i | grep "bytes from"|cut -d ' ' -f4|tr -d ':' &);done

Port scan
for p in {1..65535}; do (echo >/dev/tcp/192.168.1.1/$p) >/dev/null 2>&1 && echo "$p open"; done
