import pwndbg
import gdb
import argparse
import os
os.environ['PWNLIB_NOTERM'] = 'true'
from pwn import asm,context

# TODO: include a jmp patching option... maybe too much
parser = argparse.ArgumentParser(description="Starting at the specified address, write the assembled instructions")
parser.add_argument("address", type=int, help="The address to start assembling at")
parser.add_argument("code", type=str, default='', nargs='?', help="The code to be assembled")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def assemble(address, code):
    # Get the current architecture from pwndbg
    # Currently only supports i386 and x86_64
    try:
        context.update(arch=pwndbg.arch.current, os='linux')
    except:
        raise NotImplementedError("Unimplemented architecture: {pwndbg.arch.current}")

    # Use 0 as an address arg to create a new space
    if not pwndbg.memory.poke(address):
        if address == long(str(gdb.parse_and_eval('mmap(0x%x, 0x400, 7, 0x32, -1, 0)' % address)), 16):
            print("mmap'd at address 0x%x" % address)
        else:
            raise MemoryError("Cannot mmap at the address 0x%x" % address)

    # Allow entering assembly a line at a time until "end"
    if not code:
        print("Enter assembly instructions one per line")
        print("Enter 'EOF' when done")
        while True:
            ins = input('> ')
            if 'EOF' in ins:
                break
            code += ins + '\n'
    
    # Assemble the instructions
    # the asm function returns a tuple with the 
    # bytes being a list of ints at index 0
    asm_str = bytes(asm(code))
    
    # Write the assembled code to the specified address
    pwndbg.memory.write(address, asm_str)

