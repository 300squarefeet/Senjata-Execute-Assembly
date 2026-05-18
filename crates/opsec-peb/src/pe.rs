use crate::hash::djb2;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE:  u32 = 0x00004550;

#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

/// Resolve an exported function by DJB2(name) within an image at `base`.
/// Returns the export's RVA. For in-memory modules, absolute address = base + rva.
///
/// # Safety
/// `base` must point to a valid PE image (either loaded in-memory at its
/// preferred base, or a raw file image embedded via `include_bytes!`).
pub unsafe fn resolve_export_in_image(base: usize, name_hash: u32) -> Option<u32> {
    unsafe {
        let dos = base as *const u8;
        if core::ptr::read_unaligned(dos as *const u16) != IMAGE_DOS_SIGNATURE {
            return None;
        }
        let e_lfanew = core::ptr::read_unaligned(dos.add(0x3C) as *const u32) as usize;
        let nt = dos.add(e_lfanew);
        if core::ptr::read_unaligned(nt as *const u32) != IMAGE_NT_SIGNATURE {
            return None;
        }

        // Optional header starts after PE sig (4) + COFF header (20)
        let opt = nt.add(24);
        let magic = core::ptr::read_unaligned(opt as *const u16);
        if magic != 0x20b {
            // Only PE32+ (x64) supported
            return None;
        }

        // DataDirectory[0] (export) at opt+112 for PE32+
        let export_rva = core::ptr::read_unaligned(opt.add(112) as *const u32);
        if export_rva == 0 {
            return None;
        }

        // Parse the section table to translate RVAs to file-relative offsets.
        // COFF header: NumberOfSections at nt+6, SizeOfOptionalHeader at nt+20
        let n_sections = core::ptr::read_unaligned(nt.add(6) as *const u16) as usize;
        let size_of_opt = core::ptr::read_unaligned(nt.add(20) as *const u16) as usize;
        // Section table immediately follows optional header
        let sections_base = opt as usize + size_of_opt;

        let export_off = rva_to_offset(base, sections_base, n_sections, export_rva)?;
        let exp_dir = (base + export_off) as *const ImageExportDirectory;

        let names_rva  = (*exp_dir).address_of_names;
        let ords_rva   = (*exp_dir).address_of_name_ordinals;
        let funcs_rva  = (*exp_dir).address_of_functions;
        let n_names    = (*exp_dir).number_of_names as usize;

        let names_off = rva_to_offset(base, sections_base, n_sections, names_rva)?;
        let ords_off  = rva_to_offset(base, sections_base, n_sections, ords_rva)?;
        let funcs_off = rva_to_offset(base, sections_base, n_sections, funcs_rva)?;

        let names = (base + names_off) as *const u32;
        let ords  = (base + ords_off)  as *const u16;
        let funcs = (base + funcs_off) as *const u32;

        for i in 0..n_names {
            let name_rva = core::ptr::read_unaligned(names.add(i));
            let name_off = rva_to_offset(base, sections_base, n_sections, name_rva)?;
            let name_ptr = (base + name_off) as *const u8;
            let name_bytes = c_str_slice(name_ptr);
            if djb2(name_bytes) == name_hash {
                let ord = core::ptr::read_unaligned(ords.add(i)) as usize;
                let fn_rva = core::ptr::read_unaligned(funcs.add(ord));
                return Some(fn_rva);
            }
        }
        None
    }
}

/// Translate an RVA to a file-relative byte offset using the section table.
///
/// For an in-memory-mapped image the VirtualAddress of each section equals
/// the offset from the image base, so RVA == offset and this always returns
/// `rva as usize`.  For a raw/flat file image (e.g. `include_bytes!`) the
/// section data sits at `PointerToRawData`, not `VirtualAddress`, so we walk
/// the section table and subtract the gap.
unsafe fn rva_to_offset(
    _base: usize,
    sections_base: usize,
    n_sections: usize,
    rva: u32,
) -> Option<usize> {
    unsafe {
        // IMAGE_SECTION_HEADER is 40 bytes.
        // Fields we need:
        //   VirtualSize       offset +8   u32
        //   VirtualAddress    offset +12  u32
        //   SizeOfRawData     offset +16  u32
        //   PointerToRawData  offset +20  u32
        const SECT_SIZE: usize = 40;

        for i in 0..n_sections {
            let sh = sections_base + i * SECT_SIZE;
            let virtual_address  = core::ptr::read_unaligned((sh + 12) as *const u32);
            let size_of_raw_data = core::ptr::read_unaligned((sh + 16) as *const u32);
            let ptr_to_raw_data  = core::ptr::read_unaligned((sh + 20) as *const u32);

            let va       = virtual_address as usize;
            let raw_size = size_of_raw_data as usize;
            let raw_ptr  = ptr_to_raw_data as usize;

            let rva_us = rva as usize;
            if rva_us >= va && (rva_us) < va + raw_size {
                let offset_in_section = rva_us - va;
                return Some(raw_ptr + offset_in_section);
            }
        }
        None
    }
}

unsafe fn c_str_slice<'a>(ptr: *const u8) -> &'a [u8] {
    unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        core::slice::from_raw_parts(ptr, len)
    }
}
