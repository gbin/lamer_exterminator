from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_000
md = Cs(CS_ARCH_M68K, CS_MODE_M68K_000)


def dis(code, baseaddr):
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, baseaddr):
        _offset = address - baseaddr
        print(f'{mnemonic:10}{op_str:20} ; ${address:0x}: {code[_offset:_offset + size].hex()}')


def data(code, baseaddr):
    _addr = baseaddr
    _offset = 0

    while True:
        seg = code[_offset:_offset + 16]
        _byt = [f'{c:02x}' for c in seg]
        print(f'db.b {", ".join(_byt)} ; ${_addr:x}: {seg.decode("ascii", errors="ignore")}')
        _addr += 16
        _offset += 16
        if _offset > len(code):
            break
