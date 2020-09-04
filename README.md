![image](logo.png)
# Diffosaurus
This tool aims at improving ESIL in Radare2 by providing a convenient way to compare the execution of ESIL against a real target such as embedded device, debugged binary or emulated device (QEMU).

It allows to run a full binary/firmware or can be instructed to use provided assembly code.

It uses the gdb protocol to connect to a remote target.

# Arguments
```
  -m , --mode   Mode Selection [f]ile/[t]est
  -f , --file   File to analyse
  -t , --test   Assembly to test (wa <assembly>)
  -qb, --qbin   Qemu binary (e.g. qemu-arm)
  -qp, --qport  Qemu port (default = 1234)
  -dh, --dhost  Debugger hostname/ip (default = localhost)
  -dp, --dport  Debugger port (default = 1234)
  -D , --dback  Debugger backend (e.g. gdb-multiarch)
  -da, --dbadd  File base address (e bin.baddr)
  -a , --arch   Architecture (e asm.arch)
  -b , --bits   Architecture bits (e asm.bits)

```
# Examples
File mode (QEMU) : 
`python diffosaurus.py -m f -f binary -qp 1234 -qb qemu-arm -da 0x1000 -D gdb-multiarch -a arm -b 16`

File mode : 
`python diffosaurus.py -m f -f binary -D gdb-multiarch -a arm -b 16`

Test mode : 
`python diffosaurus.py -m t -t "MOV r1,#1;asrs r1, r1, #1;asrs r1, r1, #1" -D gdb-multiarch -a arm -b 16 -dp 3333`
