#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotPe,
    NoCor20,
    MixedMode,
    ArchMismatch,
    Malformed,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ClrVersion { V2, V4 }

pub struct AsmInfo {
    pub version: ClrVersion,
}

const DOS_MAGIC: u16 = 0x5A4D;
const NT_MAGIC: u32 = 0x00004550;
const PE32_MAGIC: u16 = 0x10B;
const PE32_PLUS_MAGIC: u16 = 0x20B;
const COMIMAGE_FLAGS_ILONLY: u32 = 0x00000001;
const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x00000002;
const METADATA_SIGNATURE: u32 = 0x424A_5342;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;

pub fn parse(bytes: &[u8]) -> Result<AsmInfo, Error> {
    if bytes.len() < 0x40 { return Err(Error::NotPe); }
    let dos_magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if dos_magic != DOS_MAGIC { return Err(Error::NotPe); }
    let e_lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    // Need at least PE signature (4) + COFF header (20) + optional header magic (2)
    if e_lfanew + 26 > bytes.len() { return Err(Error::Malformed); }
    let nt_magic = u32::from_le_bytes([bytes[e_lfanew], bytes[e_lfanew+1],
                                        bytes[e_lfanew+2], bytes[e_lfanew+3]]);
    if nt_magic != NT_MAGIC { return Err(Error::NotPe); }

    // Check COFF Machine field — reject x86-only assemblies (BOF is x64)
    let machine = u16::from_le_bytes([bytes[e_lfanew+4], bytes[e_lfanew+5]]);

    let opt = e_lfanew + 24;
    let pe_magic = u16::from_le_bytes([bytes[opt], bytes[opt+1]]);
    // DataDirectory[0] starts at opt+96 (PE32) or opt+112 (PE32+); [14] = base + 14*8
    let dd_base_offset = match pe_magic {
        PE32_PLUS_MAGIC => 112usize,
        PE32_MAGIC => 96usize,
        _ => return Err(Error::Malformed),
    };
    let cor20_rva_off = opt + dd_base_offset + 14 * 8;
    if cor20_rva_off + 8 > bytes.len() { return Err(Error::Malformed); }
    let cor20_rva = u32::from_le_bytes([
        bytes[cor20_rva_off], bytes[cor20_rva_off+1],
        bytes[cor20_rva_off+2], bytes[cor20_rva_off+3]]) as usize;
    if cor20_rva == 0 { return Err(Error::NoCor20); }

    let cor20_off = rva_to_offset(bytes, e_lfanew, cor20_rva).ok_or(Error::Malformed)?;
    if cor20_off + 72 > bytes.len() { return Err(Error::Malformed); }

    // COR20: cb(4)+maj(2)+min(2)+MetaDataRva(4)+MetaDataSize(4)+Flags(4)...
    let metadata_rva = u32::from_le_bytes([
        bytes[cor20_off+8], bytes[cor20_off+9],
        bytes[cor20_off+10], bytes[cor20_off+11]]) as usize;
    let flags = u32::from_le_bytes([
        bytes[cor20_off+16], bytes[cor20_off+17],
        bytes[cor20_off+18], bytes[cor20_off+19]]);
    if flags & COMIMAGE_FLAGS_ILONLY == 0 { return Err(Error::MixedMode); }

    // Reject x86 assemblies: PE32 with Machine==I386 AND CorFlags 32BITREQUIRED set.
    // AnyCPU assemblies are PE32 + I386 but do NOT have 32BITREQUIRED; they load fine
    // in an x64 process. Only truly x86-locked assemblies have the flag set.
    if machine == IMAGE_FILE_MACHINE_I386
        && pe_magic == PE32_MAGIC
        && (flags & COMIMAGE_FLAGS_32BITREQUIRED) != 0
    {
        return Err(Error::ArchMismatch);
    }

    let metadata_off = rva_to_offset(bytes, e_lfanew, metadata_rva).ok_or(Error::Malformed)?;
    if metadata_off + 16 > bytes.len() { return Err(Error::Malformed); }

    let sig = u32::from_le_bytes([bytes[metadata_off], bytes[metadata_off+1],
                                   bytes[metadata_off+2], bytes[metadata_off+3]]);
    if sig != METADATA_SIGNATURE { return Err(Error::Malformed); }

    let ver_len = u32::from_le_bytes([
        bytes[metadata_off+12], bytes[metadata_off+13],
        bytes[metadata_off+14], bytes[metadata_off+15]]) as usize;
    let ver_off = metadata_off + 16;
    if ver_off + ver_len > bytes.len() { return Err(Error::Malformed); }

    let ver = &bytes[ver_off..ver_off + ver_len];
    let ver_str = core::str::from_utf8(strip_nul(ver)).map_err(|_| Error::Malformed)?;
    if !ver_str.starts_with('v') { return Err(Error::Malformed); }
    let after_v = &ver_str[1..];
    let dot = after_v.find('.').ok_or(Error::Malformed)?;
    let major: u32 = after_v[..dot].parse().map_err(|_| Error::Malformed)?;
    match major {
        2 => Ok(AsmInfo { version: ClrVersion::V2 }),
        4 => Ok(AsmInfo { version: ClrVersion::V4 }),
        _ => Err(Error::Malformed),
    }
}

fn strip_nul(b: &[u8]) -> &[u8] {
    match b.iter().position(|&c| c == 0) {
        Some(i) => &b[..i],
        None => b,
    }
}

fn rva_to_offset(bytes: &[u8], e_lfanew: usize, rva: usize) -> Option<usize> {
    let n_sections = u16::from_le_bytes([bytes[e_lfanew+6], bytes[e_lfanew+7]]) as usize;
    let opt_size = u16::from_le_bytes([bytes[e_lfanew+20], bytes[e_lfanew+21]]) as usize;
    let sections_off = e_lfanew + 24 + opt_size;
    for i in 0..n_sections {
        let s = sections_off + i * 40;
        if s + 40 > bytes.len() { return None; }
        let vsize = u32::from_le_bytes([bytes[s+8], bytes[s+9], bytes[s+10], bytes[s+11]]) as usize;
        let vaddr = u32::from_le_bytes([bytes[s+12], bytes[s+13], bytes[s+14], bytes[s+15]]) as usize;
        let raw_off = u32::from_le_bytes([bytes[s+20], bytes[s+21], bytes[s+22], bytes[s+23]]) as usize;
        if rva >= vaddr && rva < vaddr + vsize {
            return Some(raw_off + (rva - vaddr));
        }
    }
    None
}


