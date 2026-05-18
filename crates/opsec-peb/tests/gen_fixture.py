"""Generate minimal x64 PE with a few exports for opsec-peb tests."""
import struct, os

def gen():
    # DOS header
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)  # e_lfanew=0x40

    # PE signature + COFF header
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH",
        0x8664,    # IMAGE_FILE_MACHINE_AMD64
        1,         # NumberOfSections
        0, 0, 0,   # timestamp, symtab ptr, n_syms
        240,       # SizeOfOptionalHeader (PE32+)
        0x2002)    # Characteristics: EXECUTABLE_IMAGE | DLL

    # Optional header (PE32+, abbreviated for fixture)
    opt = bytearray(240)
    opt[0:2] = struct.pack("<H", 0x20b)  # PE32+ magic
    export_rva = 0x1000  # virtual address
    export_size = 0x100
    opt[112:120] = struct.pack("<II", export_rva, export_size)  # DataDirectory[0]

    # Section header
    sect = b".rdata\x00\x00" + struct.pack("<IIIIIIHHI",
        0x1000,    # VirtualSize
        0x1000,    # VirtualAddress
        0x200,     # SizeOfRawData
        0x200,     # PointerToRawData
        0, 0, 0, 0, 0x40000040)

    # Pad to 0x200
    header_end = len(dos) + len(pe_sig) + len(coff) + len(opt) + len(sect)
    pad = b"\x00" * (0x200 - header_end)

    names = [b"foo\x00", b"bar\x00", b"baz\x00"]
    dll_name_offset = 0x46  # offset from section base
    name_strings_offset = dll_name_offset + len(b"fixture.dll\x00")

    name_rvas = []
    cur = 0x1000 + name_strings_offset
    for n in names:
        name_rvas.append(cur)
        cur += len(n)

    export_dir = struct.pack("<IIHHIIIIIII",
        0, 0,                       # Characteristics, TimeDateStamp
        0, 0,                       # Major/Minor version
        0x1000 + dll_name_offset,   # Name RVA
        1,                          # Base
        len(names),                 # NumberOfFunctions
        len(names),                 # NumberOfNames
        0x1028,                     # AddressOfFunctions RVA
        0x1034,                     # AddressOfNames RVA
        0x1040)                     # AddressOfNameOrdinals RVA

    funcs = struct.pack("<III", 0x2000, 0x2010, 0x2020)
    name_table = b"".join(struct.pack("<I", r) for r in name_rvas)
    ords = struct.pack("<HHH", 0, 1, 2)
    dll_name = b"fixture.dll\x00"
    name_strings = b"".join(names)

    section_data = (export_dir + funcs + name_table + ords +
                    dll_name + name_strings)
    section_data += b"\x00" * (0x200 - len(section_data))

    fixture_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(fixture_dir, "fixtures", "mini-pe.bin")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(dos + pe_sig + coff + opt + sect + pad + section_data)
    print(f"Wrote {out_path}")

if __name__ == "__main__":
    gen()
