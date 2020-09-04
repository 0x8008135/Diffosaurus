import r2pipe
import subprocess
import time
from tqdm import tqdm
from wasabi import color 
import argparse

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


def print_logo():
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
                                                           \n"
    
    print("".join(color(x, fg=16, bg="red") if x == "@" else x for x in logo))
    print("".join(color(x[0:25], fg=16, bg="red")+x[25:]+"\n" for x in banner.split("\n")))


if __name__ == '__main__':
    print_logo()
    parser = argparse.ArgumentParser(description="Diffosaurus - ESIL differential analysis\n\n\
        [Examples]\n\
        File mode: python diffosaurus.py -m f -f ./binaries/aes_thumb -qp 1234 -qb qemu-arm -da 0x1000 -D gdb-multiarch -a arm -b 16\n\
        Test mode: python diffosaurus.py -m t -t \"MOV r1,#1;asrs r1, r1, #1;asrs r1, r1, #1\" -D gdb-multiarch -a arm -b 16 -dp 3333\n\n")
    parser.add_argument("-m",  "--mode", dest="mode", action="store", required=True, help="Mode Selection [f]ile/[t]est")
    parser.add_argument("-f",  "--file", dest="dbg_file", action="store", default="-", help="File to analyse")
    parser.add_argument("-t",  "--test", dest="test", action="store", help="Assembly to test (wa <assembly>")
    parser.add_argument("-qb", "--qbin", dest="qb", action="store", help="Qemu binary (e.g. qemu-arm)")
    parser.add_argument("-qp", "--qport", dest="qp", action="store", default="1234", help="Qemu port (default = %(default)s)")
    parser.add_argument("-dh", "--dhost", dest="dbg_host", action="store", default="localhost", help="Debugger hostname/ip (default = %(default)s)")
    parser.add_argument("-dp", "--dport", dest="dbg_port", action="store", default="1234", help="Debugger port (default = %(default)s)")
    parser.add_argument("-D",  "--dback", dest="dbg_backend", action="store",  required=True, default="gdb-multiarch", help="Debugger backend (e.g. gdb-multiarch)")
    parser.add_argument("-da", "--dbadd", dest="dbg_baddr", action="store", help="File base address (e bin.baddr)")
    parser.add_argument("-a",  "--arch", dest="arch", action="store", required=True, help="Architecture (e asm.arch")
    parser.add_argument("-b",  "--bits", dest="bits", action="store", required=True, help="Architecture bits (e asm.bits)")   
    
    result = parser.parse_args()
    
    esl_old_instr = ""
    dbg_old_instr = ""

    if (result.mode == 't'):
        sram = input("Enter SRAM location (e.g. 0x20000000): ")
        sp = input("Enter SP location (e.g. 0x20000100): ")

        # ESIL
        r2_esl = r2pipe.open("-")
        r2_esl.cmd("e io.cache=true")
        r2_esl.cmd("e asm.arch=" + result.arch)
        r2_esl.cmd("e asm.bits=" + result.bits)
        r2_esl.cmd("aei")
        r2_esl.cmd("aeim")
        r2_esl.cmd("aeip")    
        r2_esl.cmd(f"omb. {sram}")
        r2_esl.cmd(f"aro;ar PC={sram};ar SP={sp};")
        r2_esl.cmd(f"s {sram}")
        r2_esl.cmd(f"\"wa {result.test}\"")

        # DEBUG
        r2_dbg=r2pipe.open("gdb://"+result.dbg_host+":"+ result.dbg_port, flags=["-D "+ result.dbg_backend])
        r2_dbg.cmd("e dbg.bpinmaps=0")
        r2_dbg.cmd("e asm.arch=" + result.arch)
        r2_dbg.cmd("e asm.bits=" + result.bits)
        r2_dbg.cmd(f"dr PC={sram};dr SP={sp};")
        r2_dbg.cmd(f"s {sram}")
        r2_dbg.cmd(f"\"wa {result.test}\"")
        
        registers = filter_registers()

        # sync regs before start
        #reg_e2t_sync() #esil > target
    else:
        # ESIL
        r2_esl = r2pipe.open(result.dbg_file)
        r2_esl.cmd("e io.cache=true")
        r2_esl.cmd("e asm.arch=" + result.arch)
        r2_esl.cmd("e asm.bits=" + result.bits)
        r2_esl.cmd("aei")
        r2_esl.cmd("aeim")
        r2_esl.cmd("aeip")
    
        # QEMU
        if (result.qb):
            subprocess.Popen(args=[result.qb,"-singlestep","-g", result.qp, result.dbg_file])
    
        dbg_flags = ["-e dbg.exe.path=" + result.dbg_file,"-D "+ result.dbg_backend, "-d"]

        if (result.dbg_baddr):
            dbg_flags = ["-e bin.baddr=" + result.dbg_baddr] + dbg_flags

        # DEBUG
        r2_dbg=r2pipe.open("gdb://" + result.dbg_host + ":" + result.dbg_port, flags=dbg_flags)
        r2_dbg.cmd("e io.cache=true")
        r2_dbg.cmd("e dbg.bpinmaps=0")
        r2_dbg.cmd("e asm.arch=" + result.arch)
        r2_dbg.cmd("e asm.bits=" + result.bits)

        registers = filter_registers()
        
        # stack copy qemu arm
        if ( result.arch.lower() == "arm" and result.qb ):
            sp = int(get_debug_registers()['sp'],0)
            sp_start = sp & 0xfffff000 
            sp_end  = sp + 0x1000
            chunk=16
            
            for x in tqdm(range(sp_start,sp_end,chunk)):
                a=r2_dbg.cmd(f'"p8 {chunk}" @{hex(x)}')
                r2_esl.cmd(f'"wx {a.strip()}" @{hex(x)}')    
        
        # sync regs before start
        #reg_t2e_sync() #target > esil
    
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
        r2_esl.cmd("aes")
        r2_dbg.cmd("ds")
        print("\n\n\n")
        
    r2_esl.quit()
    r2_dbg.quit()   
