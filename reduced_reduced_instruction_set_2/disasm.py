def decode(buf: bytes) -> str:
    if buf == b'SMOL':
        return 'HEADER'
    match buf[0]:
        case 0:
            return 'mov', buf[1], buf[2]
        case 1:
            return 'add3_imm8', buf[1], buf[2], buf[3]
        case 2:
            return 'add3_imm8_v2', buf[1], buf[2], buf[3]
        case 3:
            return 'print_addr', buf[1]
        case 4:
            return 'mov_imm8', buf[1], buf[3]
        case 5:
            return 'push', buf[2]
        case 6:
            return 'pop', buf[1]
        case 7:
            return 'test_sub', buf[1], buf[2]
        case 8:
            return 'jz_rel', buf[2] * 8 + buf[3]
        case 9:
            return 'print_nbytes', buf[3]
        case 10:
            return 'mul_add_imm8', buf[1], buf[2], buf[3]
        case 11:
            return 'add2_imm8', buf[1], buf[2], buf[3]
        case 12:
            return 'halt'
        case 13:
            return 'scan', buf[1]
        case 14:
            return 'xor', buf[1], buf[2]
        case 15:
            return 'shr', buf[1], buf[3] & 0x1f
        case 16:
            return 'getch', buf[1]
        case 17:
            return 'shl', buf[1], buf[3] & 0x1f
        case 18:
            return 'sub2_imm8', buf[1], buf[3]
        case 19:
            return 'mod', buf[1], buf[2]
        
def beautify(buf: bytes, rip: int) -> str:
    if buf == b'SMOL':
        return '# HEADER'
    match buf[0]:
        case 0:
            return f'r[{buf[1]}] = r[{buf[2]}]'
        case 1:
            return f'r[{buf[1]}] += r[{buf[2]}] + {buf[3]}'
        case 2:
            return f'r[{buf[1]}] += r[{buf[2]}] + {buf[3]}'
        case 3:
            return f'print(r[{buf[1]}])'
        case 4:
            return f'r[{buf[1]}] = {buf[3]}'
        case 5:
            return f'r[6] += 8\n\tstack[r[6]] = r[{buf[2]}]'
        case 6:
            return f'r[{buf[1]}] = stack[r[6]]\n\tr[6] -= 8'
        case 7:
            return f'print("[DEBUG] Testing @{rip} 2 values", r[{buf[1]}], r[{buf[2]}], hex(r[{buf[1]}]))\n\tr[4] = r[{buf[1]}] - r[{buf[2]}]'
        case 8:
            # Because we also counts header/magic to be a line, we have to add 4 to pad
            return f'if r[4] == 0:\n\t\tip{rip + buf[2] * 0x100 + buf[3] + 4}()'
        case 9:
            # return f'print(stack[r[6]:][:{buf[3]}])'
            return f'print(binascii.a2b_hex("".join([hex(stack[r[6]])[2:]]).rjust(8, "0"))[::-1].decode(), end="")'
        case 10:
            return f'r[{buf[1]}] = r[{buf[1]}] * r[{buf[2]}] + {buf[3]}'
        case 11:
            return f'r[{buf[1]}] += {buf[3]}'
        case 12:
            return f'print("[DEBUG] Return at line {rip}")\n\treturn'
        case 13:
            return f'r[{buf[1]}] = int(input())'
        case 14:
            return f'r[{buf[1]}] = r[{buf[1]}] ^ r[{buf[2]}]'
        case 15:
            return f'r[{buf[1]}] = r[{buf[1]}] >> ({buf[3]} & 0x1f)'
        case 16:
            return f'r[{buf[1]}] = ord(sys.stdin.read(1))'
        case 17:
            return f'r[{buf[1]}] = r[{buf[1]}] << ({buf[3]} & 0x1f)'
        case 18:
            return f'r[{buf[1]}] -= {buf[3]}'
        case 19:
            return f'r[{buf[1]}] = r[{buf[1]}] % r[{buf[2]}]'

def compile():
    idx = 0
    print('''
import sys
import binascii
sys.setrecursionlimit(10000)
r = [0] * 8
a = []
stack = [0] * (1 << 20)''')
    with open('password_checker2.smol', "rb") as f:
        while (buf := f.read(4)) != b'':
            print(f'def ip{idx}():')
            print('\t"""', buf, decode(buf), '"""')
            # print(f'\tprint("[DEBUG] Line {idx}")')
            print('\t' + beautify(buf, idx))
            idx += 4
            print(f'\tip{idx}()')

    print(f'def ip{idx}():')
    print(f'\treturn')

    print("ip0()")

def disasm():
    idx = 0
    with open('password_checker2.smol', "rb") as f:
        while (buf := f.read(4)) != b'':
            print(f'L{idx}:\t', decode(buf))
            idx += 4

disasm()
# compile()