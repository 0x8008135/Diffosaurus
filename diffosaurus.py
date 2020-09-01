import r2pipe
import subprocess
import time
from tqdm import tqdm
from wasabi import color 

debug = False
old_c = ''
registers = []

def cls():
    print("\x1B[2J")


def diff_strings(a, b):
    output = []
    m=False
    for c in range(len(a)):
        if (a[c] != b[c]):
            output.append(color(a[c], fg=16, bg="red"))
            m = True
        else:
            output.append(b[c])

    return ("".join(output), m)


def filter_registers():
    regs_esl = dict(x.split(" = ") for x in r2_esl.cmd("aer").split("\n")[:-1])
    regs_dbg = dict(x.split(" = ") for x in r2_dbg.cmd("dr").split("\n")[:-1])
    regs=[x for x in regs_dbg.keys() if x in regs_esl.keys()]
    return regs


def get_esil_registers():
    regs_esl = {}
    regs_esl = dict(x.split(" = ") for x in r2_esl.cmd("aer").split("\n")[:-1])
    if debug:
        for x in regs_esl:
            print(f"{x}\t{regs_esl[x]}")

    for k in list(regs_esl.keys()):
        if k not in registers:
            del regs_esl[k]

    return regs_esl


def get_debug_registers():
    regs_dbg = {}
    regs_dbg = dict(x.split(" = ") for x in r2_dbg.cmd("dr").split("\n")[:-1])
    if debug:
        for x in regs_dbg:
            print(f"{x}\t{regs_dbg[x]}")

    for k in list(regs_dbg.keys()):
        if k not in registers:
            del regs_dbg[k]

    return regs_dbg


def reg_t2e_sync():
    regs_dbg = get_debug_registers()
    for x in regs_dbg:
        r2_esl.cmd(f"aer {x}={regs_dbg[x]}")

    if debug:
        print(get_esil_registers())


def reg_e2t_sync():
    regs_esl = get_esil_registers()
    for x in regs_esl:
        r2_dbg.cmd(f"dr {x}={regs_esl[x]}")

    if debug:
        print(get_debug_registers())


def print_regs(regs_dbg,regs_esl):
    global debug
    global old_c
    modified = False
    
    print(f"REG\tDEBUG\t\tESIL")

    for x in regs_esl:
        diffs,m = diff_strings(regs_esl[x],regs_dbg[x])
        if m == True:
            modified = True
        print(f"{x}\t{regs_dbg[x]}\t{diffs}")

    if modified ==True:
        while True:
            c=input("\nOooops something changed!\n[d]isplay registers\n[e]sil -> TARGET\n[t]arget -> ESIL\n[s]tep\n[i]nteractive\n[v]erbose\n[q]uit\n")
            if c == '':
                c = old_c
            if c == 't':
                reg_t2e_sync() #target > esil
                old_c = c
                break
            elif c == 'e':
                reg_e2t_sync() #esil > target
                old_c = c
                break
            elif c == 'q':
                exit()
            elif c == 'v':
                debug = False if debug else True
            elif c == 's':
                break
            elif c == 'd':
                print(f"REG\tTARGET\t\tESIL")
                for x in regs_esl:
                    diffs,m = diff_strings(regs_esl[x],regs_dbg[x])
                    print(f"{x}\t{regs_dbg[x]}\t{diffs}")

            elif c == 'i':
                while c!= 'q':
                    c = input("[b]oth || [e]sil || [t]arget || [q]uit ?\n")
                    if c == 'e':
                        print(r2_esl.cmd(input("ESIL cmd: ")))
                    elif c == 't':
                        print(r2_dbg.cmd(input("TARGET cmd: ")))
                    elif c == 'b':
                        cmd=input("CMD: ")
                        print("[DEBUG]\n")
                        print(r2_dbg.cmd(cmd))
                        print("[ESIL]\n")
                        print(r2_esl.cmd(cmd))
            old_c = c


logo="\n\
                                      @@\n\
                                     @██@\n\
                         @          @████@\n\
                        @█@        @███████@\n\
                       @███@      @█████████@\n\
                      @█████@    @███████████@    @       @       @\n\
                @@   @███████@  @█████████████@  @█@@    @█@@    @█@@\n\
               @██@ @█████████@@███████████████@████@███████@███████@@@@@@@@\n\
              @████@███████████@██████████████████████████████@@@@@@\n\
      @      @██████@███████████████████████████████████@@@@@@\n\
     @@@    @██████████████████████████████████████@@@@\n\
    ███@@  @███████████████████████████████████@@@\n\
 ████@███@@█████████████████████████@@██████@@\n\
  ███████████████████████████████@@@███████@\n\
    ██████████████████@@@@@@@@@@@█████████@\n\
             ████ ████          ████ █████\n\
               ███ ████         ███ █████\n\
               ███ ████         ███ █████\n\
              ███ ████          ███ █████\n\
             ███ ████          ███ █████\n\
             @@@ @@@@          @@@ @@@@@ \n\
\n"

banner="\
 ____  _  __  __                                       \n\
|  _ \(_)/ _|/ _| ___  ___  __ _ _   _ _ __ _   _ ___  \n\
| | | | | |_| |_ / _ \/ __|/ _` | | | | '__| | | / __| \n\
| |_| | |  _|  _| (_) \__ \ (_| | |_| | |  | |_| \__ \ \n\
|____/|_|_| |_|  \___/|___/\__,_|\__,_|_|   \__,_|___/ \n\
                                                       \n\
"

print("".join(color(x, fg=16, bg="red") if x == "@" else x for x in logo))
print("".join(color(x[0:25], fg=16, bg="red")+x[25:]+"\n" for x in banner.split("\n")))

debug_file="./binaries/aes_thumb"

#DEBUG
subprocess.Popen(args=["qemu-arm","-singlestep","-g","1234",debug_file])

r2_dbg=r2pipe.open("gdb://127.0.0.1:1234", flags=["-e bin.baddr=0x10000","-e dbg.exe.path="+debug_file,"-D gdb-multiarch", "-d"])

r2_dbg.cmd("e io.cache=true")
r2_dbg.cmd("e asm.arch=arm")
r2_dbg.cmd("e asm.bits=16")
r2_dbg.cmd("e dbg.bpinmaps=0")

#ESIL
r2_esl=r2pipe.open(debug_file)
r2_esl.cmd("e io.cache=true")
r2_esl.cmd("e asm.arch=arm")
r2_esl.cmd("e asm.bits=16")
r2_esl.cmd("aei")
r2_esl.cmd("aeim")
r2_esl.cmd("aeip")

esl_old_instr=""
dbg_old_instr=""

registers = filter_registers()

# Copy stack ARM specific
sp = int(get_debug_registers()['sp'],0)
print(hex(sp))
sp_start = sp & 0xfffff000 
sp_end  = sp + 0x1000
chunk=16

for x in tqdm(range(sp_start,sp_end,chunk)):
    a=r2_dbg.cmd(f'"p8 {chunk}" @{hex(x)}')
    r2_esl.cmd(f'"wx {a.strip()}" @{hex(x)}')

#print(r2_dbg.cmd(f'"p8 0x100" @{hex(sp+0x100)}'))
#print(r2_esl.cmd(f'"p8 0x100" @{hex(sp+0x100)}'))


# sync regs before start
reg_t2e_sync() #target > esil

while True:
    print("ESIL:")
    print(f"[--] {esl_old_instr}")
    esl_old_instr=r2_esl.cmd('pdt 1 @pc')
    print(f"[PC] {esl_old_instr}")
    print("DEBUG:")
    print(f"[--] {dbg_old_instr}")
    dbg_old_instr=r2_dbg.cmd('pdt 1 @pc')
    print(f"[PC] {dbg_old_instr}")
    print_regs(get_debug_registers(),get_esil_registers())
    esl_old_instr=r2_esl.cmd('pdt 1 @pc')
    dbg_old_instr=r2_dbg.cmd('pdt 1 @pc')
    time.sleep(0.25)
    r2_esl.cmd("aes")
    r2_dbg.cmd("ds")
    #print("\n\n\n")
    cls()
    #print("\x1B[2J")
    
r2_esl.quit()
r2_dbg.quit()   


#EXAMPLE for tests
#tests = [
#	"MOV r1,#1;asrs r1, r1, #1;asrs r1, r1, #1",
#	"MOV r1,#1;RSB r1,#1280;RSB r1,#1280",
#	"MOV r1,#16;cmp r1, #16;cmp r1, #1",
#	"SUB r1,8;asrs r1, r1, #2;asrs r1, r1, #2",
#	"MOV r1,#0x0;SUBS r1,#1;SUBS r1,#1",
#	"MOV r1,#0xffffffff;ADDS r1,#1",
#	"MOV r1,#0xffffffff;MOV r3,#0xffffffff;ADCS r1, r3;ADCS r1, r3;ADCS r1,r3",
#	"MOV r1,#0x90000000;MOV r3,#0x80000000;ADCS r1, r3;ADCS r1, r3;ADCS r1,r3",
#	"loop:;MOV r1,#0x80000000;LSRS r1,r2;ADD r2,1;CMP R2,#31;BLT loop",
#	"loop:;MOV r1,1;LSLS r1,r2;ADD r2,1;CMP R2,#31;BLT loop"
#]
#
#for x in tests:
#    #Target ESIL
#    sram = "0x20000000"
#    sp   = "0x20000400"
#    fp   = "0x0"
#    r2_esl=r2pipe.open("-")
#    r2_esl.cmd("e asm.arch=arm;e asm.bits=16")
#    r2_esl.cmd("aei;aeim;aeip")
#    r2_esl.cmd(f"omb. {sram}")
#    r2_esl.cmd(f"aro;ar pc={sram};ar sp={sp};ar fp={fp}")
#    r2_esl.cmd(f"ar lr=0xffffffff")
#    r2_esl.cmd(f"s {sram}")
#    r2_esl.cmd(f"\"wa {x} ;MOV r5,1\"")
