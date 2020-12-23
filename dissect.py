#!/usr/bin/env python3
from helpers import data, dis

CODE = bytearray(open('disk.adf', 'rb').read())

print('/* vim: set ft=asm68k: */')
print('; header')
data(CODE[0:12], 0x1558)

CODE = CODE[12:]
BASEADDR = 0x1564

print()
print('; entry point')
dis(CODE, BASEADDR)

print()
print()
print('; Decryption routine')
entry_point_decrypt = 0x158a
end_point_decrypt = 0x15a6
entry_offset = entry_point_decrypt - BASEADDR
end_offset = end_point_decrypt - BASEADDR
dis(CODE[entry_offset:end_offset], entry_point_decrypt)


# Decrypting the second part of the boot block

first_seed = 0x81
second_seed = CODE[0x18f9 - BASEADDR]
NB_BYTES_TO_CONVERT = 0x352
to_convert = NB_BYTES_TO_CONVERT
encrypted_addr = end_point_decrypt

while to_convert != 0:
    CODE[encrypted_addr-BASEADDR] = (CODE[encrypted_addr-BASEADDR] + second_seed) % 256
    CODE[encrypted_addr-BASEADDR] = (CODE[encrypted_addr-BASEADDR] ^ first_seed) % 256
    to_convert -= 1
    encrypted_addr += 1

print()
print()
print('; After decryption')
dis(CODE[entry_offset:entry_offset + NB_BYTES_TO_CONVERT - 16], entry_point_decrypt)

SECOND_DATA = 0x18cc
print('; Trailing data')
data(CODE[SECOND_DATA - BASEADDR: 1024 - 12], SECOND_DATA)



