# Volatility 2

```bash
python2 vol.py -f recollection.bin imageinfo
python2 vol.py -f recollection.bin --profile=Win7SP1x64 clipboard
python2 vol.py -f recollection.bin --profile=Win7SP1x64 cmdscan
python2 vol.py -f recollection.bin --profile=Win7SP1x64 consoles
python2 vol.py -f recollection.bin --profile=Win7SP1x64 cmdline
python2 vol.py -f recollection.bin --profile=Win7SP1x64 pslist
python2 vol.py -f recollection.bin --profile=Win7SP1x64 pstree
python2 vol.py -f recollection.bin --profile=Win7SP1x64 netscan
python2 vol.py -f recollection.bin --profile=Win7SP1x64 filescan | grep "passwords.txt"
python2 vol.py -f recollection.bin --profile=Win7SP1x64 dumpfiles -Q 0xOFFSET --dump-dir ./out
```



# Volatility 3

```
vol -f "FILE" windows."command"


windows.info
```
