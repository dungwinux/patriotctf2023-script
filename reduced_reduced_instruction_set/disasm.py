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
            return 'sub', buf[1], buf[2]
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
            return f'print("Testing 2 values", r[{buf[1]}], r[{buf[2]}], hex(r[{buf[1]}]))\n\tr[4] = r[{buf[1]}] - r[{buf[2]}]'
        case 8:
            # Because we also counts header/magic to be a line, we have to add 4 to pad
            return f'if r[4] == 0:\n\t\tip{rip + buf[2] * 0x100 + buf[3] + 4}()'
        case 9:
            return f'print(stack[r[6]:][:{buf[3]}])'
        case 10:
            return f'r[{buf[1]}] = r[{buf[1]}] * r[{buf[2]}] + {buf[3]}'
        case 11:
            return f'r[{buf[1]}] += {buf[3]}'
        case 12:
            return f'print("[DEBUG] Return at line {rip}")\n\treturn'
        case 13:
            return f'r[{buf[1]}] = int(input())'

        

idx = 0
print('''
import sys
sys.setrecursionlimit(10000)
r = [0] * 8
a = []
stack = [0] * (1 << 20)
''')
with open('password_checker.smol', "rb") as f:
    while (buf := f.read(4)) != b'':
        print(f'def ip{idx}():')
        print('\t"""', buf, decode(buf), '"""')
        print('\t' + beautify(buf, idx))
        idx += 4
        # print(f'\tprint("[DEBUG] Line {idx}")')
        print(f'\tip{idx}()')

print(f'def ip{idx}():')
print(f'\treturn')

print("ip0()")