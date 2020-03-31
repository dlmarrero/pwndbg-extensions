'''
Adds the 'assemble' command to pwndbg
Allows you to run `assemble 0xdeadbeef "xor eax, eax; ret"`

Or enter multiple lines of assembly and terminate with 'end'
```
assemble 0xdeadbeef
xor eax, eax
sub eax, 0xfffffffe
ret
end
```

Depends on keystone-engine, which pip installs all dumb so you have to run
these commands to get it to work (sudo):
python3 -m pip install keystone-engine
mv /usr/local/lib/python3.7/dist-packages/usr/lib/python3/dist-packages/keystone/libkeystone.so \
   /usr/local/lib/python3.7/dist-packages/keystone/
'''
import pwndbg
import argparse
from keystone import *

parser = argparse.ArgumentParser(description="Starting at the specified address, write the assembled instructions")
parser.add_argument("address", type=int, help="The address to start assembling at")
parser.add_argument("code", type=str, default='', nargs='?', help="The code to be assembled")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def assemble(address, code):
    # Get the current architecture from pwndbg
    # Currently only supports i386 and x86_64
    if pwndbg.arch.current == 'i386':
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
    elif pwndbg.arch.current == 'x86-64':
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    else:
        raise NotImplementedError(f"Unimplemented architecture: {pwndbg.arch.current}")

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
    asm = bytes(ks.asm(code)[0])
    
    # Write the assembled code to the specified address
    pwndbg.memory.write(address, asm)

