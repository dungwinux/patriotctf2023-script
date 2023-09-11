def f_complex(p1, p2):
    if p1 > 64 and p1 < 126:
        x = (p2 + 65) % 122
        if x < 65:
            x += 61
        return x
    print("Suboptimal")
    assert 1 == 0

def f_complex2(p1, p2):
    x = (p2 + 65) % 122
    if x < 65:
        x += 61
    return x

def calc(c):
    c = f_complex(c, c)
    c = f_complex2(c, c)
    return c

def calc_rev(p):
    non_sub = lambda x: x
    sub = lambda x: x - 61
    xs = [p, p - 61]
    xs = [x for x in xs if x > 0]
    xs = [(x + i * 122 - 65) for x in xs for i in range(2)]
    xs = [x for x in xs if x > 0]
    xs = [f(x) for x in xs for f in (non_sub, sub)]
    xs = [x for x in xs if x > 0]
    xs = [(x + i * 122 - 65) for x in xs for i in range(2)]
    xs = [x for x in xs if x > 64 and x < 126]
    return xs[0]

print(bytes([calc_rev(ord(x)) for x in "xk|nF{quxzwkgzgwx|quitH"]))