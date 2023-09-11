import sys

def decode(buf: bytes):
    if buf == b'SMOL':
        return 'HEADER', ''
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
            return 'halt', ''
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

def beautify(buf: bytes, rip: int, second_call) -> str:
    if buf == b'SMOL':
        return '// HEADER'
    match buf[0]:
        case 0:
            return f'r[{buf[1]}] = r[{buf[2]}];'
        case 1:
            return f'r[{buf[1]}] += r[{buf[2]}] + {buf[3]};'
        case 2:
            return f'r[{buf[1]}] += r[{buf[2]}] + {buf[3]};'
        case 3:
            return f'printf("%lu\\n", r[{buf[1]}]);'
        case 4:
            return f'r[{buf[1]}] = {buf[3]};'
        case 5:
            return f'r[6] += 8; stack[r[6]] = r[{buf[2]}];'
        case 6:
            return f'r[{buf[1]}] = stack[r[6]]; r[6] -= 8;'
        case 7:
            return f'printf("[DEBUG] Testing @{rip} 2 values %d %d\\n", r[{buf[1]}], r[{buf[2]}]);\n\tr[4] = r[{buf[1]}] - r[{buf[2]}];'
        case 8:
            # Because we also counts header/magic to be a line, we have to add 4 to pad
            dest = rip + buf[2] * 0x100 + buf[3] + 4
            second_call.append(dest)
            return f'if (r[4] == 0) ip{dest}();'
        case 9:
            return f'for (int _ = 0; _ < {buf[3]}; ++_) printf("%c", *((char*)(&stack[r[6]]) + _));'
        case 10:
            return f'r[{buf[1]}] = r[{buf[1]}] * r[{buf[2]}] + {buf[3]};'
        case 11:
            return f'r[{buf[1]}] += {buf[3]};'
        case 12:
            return f'puts("[DEBUG] Return at line {rip}");\n\treturn;'
        case 13:
            return f'puts("[DEBUG] Read number at line {rip}");scanf("%lu", &r[{buf[1]}]);'
        case 14:
            return f'r[{buf[1]}] = r[{buf[1]}] ^ r[{buf[2]}];'
        case 15:
            return f'r[{buf[1]}] = r[{buf[1]}] >> ({buf[3]} & 0x1f);'
        case 16:
            return f'puts("[DEBUG] Read character at line {rip}");r[{buf[1]}] = getchar();'
        case 17:
            return f'r[{buf[1]}] = r[{buf[1]}] << ({buf[3]} & 0x1f);'
        case 18:
            return f'r[{buf[1]}] -= {buf[3]};'
        case 19:
            return f'r[{buf[1]}] = r[{buf[1]}] % r[{buf[2]}];'

def wrap_fn(idx, idx_next, func):
    return (f'void ip{idx}()') + (' {\n') + func + (f'\n\tip{idx_next}();') + ('}')


def compile():
    idx = 0
    print('''
    #include <cstdio>
    #include <vector>
    int32_t r[8] = {0};
    std::vector<uint64_t> stack (1 << 16);
    ''')
    prog = {}
    second_call = [0]
    with open('password_checker2.smol', "rb") as f:
        while (buf := f.read(4)) != b'':
            func =  '\t' + beautify(buf, idx, second_call) + '\t //' + str(decode(buf)) + '\n'
            prog[idx] = func
            idx += 4
    print(f'void ip{idx}()')
    print('{')
    print(f'\treturn;')
    print('}')
    second_call.append(idx)

    second_call = list(set(second_call))
    second_call.sort()

    # Pre-define
    for x in second_call:
        print(f'void ip{x}();')
    start = 0
    for end_point in second_call[1:]:
        # Flattening function
        f = ';'.join([prog[x] for x in range(start, end_point, 4)])
        print(wrap_fn(start, end_point, f))
        start = end_point

    print("int main() {ip0();}")

def key_extract_pass():
    asm = []
    with open('password_checker2.smol', "rb") as f:
        while (buf := f.read(4)) != b'':
            asm.append(decode(buf))

    # Extract key checker - Pass
    expect = ''
    for idx, ins in enumerate(asm):
        if 'test_sub' == ins[0]:
            checker_start = idx - 1
            while 'push' != asm[checker_start][0]:
                checker_start = checker_start - 1
            key_elem = [x for x in asm[checker_start:idx] if x[0] == 'mov_imm8']
            # print(key_elem)
            # ((? ^ xorer) + imm) % mod == comp
            xorer = key_elem[0][2] if len(key_elem) == 4 else 0
            imm = key_elem[-3][2]
            mod = key_elem[-2][2]
            comp = key_elem[-1][2]

            if comp < imm:
                comp += mod
            answer = (comp - imm) ^ xorer

            print("Key checker found @{}: {} {} {} {} -> {}".format(idx * 4, xorer, imm, mod, comp, answer))
            expect += chr(answer)
    print('Full recovered key:')
    print(expect)

if __name__ == "__main__":
    if sys.argv[-1] == 'x':
        key_extract_pass()
    else:
        compile()