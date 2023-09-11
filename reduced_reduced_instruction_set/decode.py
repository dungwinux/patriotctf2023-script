import binascii

key = [
    1885566054,
    2071358815,
    1915975269,
    1920152425,
    1850171185,
    1935635570,
    2100310064,
]

print(binascii.a2b_hex("".join([hex(x)[2:] for x in key])))