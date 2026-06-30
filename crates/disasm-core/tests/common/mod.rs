//! Shared test-fixture builders: synthesize a real ELF (via `object::write`) and
//! a minimal hand-crafted PE32+ so the container parse + sweep path is exercised
//! deterministically, without committing opaque binaries or needing a toolchain.
//! (A committed real arm64 Mach-O fixture covers the Mach-O + imports path.)

#![allow(dead_code)]

use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

/// Build a real ELF (relocatable object) for X86-64 with a `.text` section
/// containing `code` and a `_start` symbol marking it.
pub fn build_elf_x64(code: &[u8]) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = obj.section_id(StandardSection::Text);
    obj.append_section_data(text, code, 16);
    obj.add_symbol(Symbol {
        name: b"_start".to_vec(),
        value: 0,
        size: code.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    obj.write().unwrap()
}

/// Image base used by [`build_pe_x64`].
pub const PE_IMAGE_BASE: u64 = 0x1_4000_0000;
/// `.text` RVA (and entry RVA) used by [`build_pe_x64`].
pub const PE_TEXT_RVA: u32 = 0x1000;

/// Build a minimal but valid PE32+ (AMD64) executable with one executable
/// `.text` section containing `code`, entry pointing at it.
pub fn build_pe_x64(code: &[u8]) -> Vec<u8> {
    const FILE_ALIGN: usize = 0x200;
    const SECT_ALIGN: usize = 0x1000;
    let headers_size = FILE_ALIGN;
    let mut buf = vec![0u8; headers_size];

    // DOS header: "MZ" + e_lfanew @ 0x3c.
    buf[0] = b'M';
    buf[1] = b'Z';
    let e_lfanew: u32 = 0x80;
    buf[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    let mut o = e_lfanew as usize;
    buf[o..o + 4].copy_from_slice(b"PE\0\0");
    o += 4;

    // COFF header.
    buf[o..o + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
    buf[o + 2..o + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    let opt_size: u16 = 0xF0;
    buf[o + 16..o + 18].copy_from_slice(&opt_size.to_le_bytes()); // SizeOfOptionalHeader
    buf[o + 18..o + 20].copy_from_slice(&0x22u16.to_le_bytes()); // Characteristics
    o += 20;

    // Optional header (PE32+).
    let opt = o;
    buf[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // Magic: PE32+
    buf[opt + 16..opt + 20].copy_from_slice(&PE_TEXT_RVA.to_le_bytes()); // AddressOfEntryPoint
    buf[opt + 20..opt + 24].copy_from_slice(&PE_TEXT_RVA.to_le_bytes()); // BaseOfCode
    buf[opt + 24..opt + 32].copy_from_slice(&PE_IMAGE_BASE.to_le_bytes()); // ImageBase
    buf[opt + 32..opt + 36].copy_from_slice(&(SECT_ALIGN as u32).to_le_bytes()); // SectionAlignment
    buf[opt + 36..opt + 40].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes()); // FileAlignment
    buf[opt + 40..opt + 42].copy_from_slice(&6u16.to_le_bytes()); // MajorOSVersion
    buf[opt + 48..opt + 50].copy_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
    let size_of_image = PE_TEXT_RVA as usize + SECT_ALIGN;
    buf[opt + 56..opt + 60].copy_from_slice(&(size_of_image as u32).to_le_bytes()); // SizeOfImage
    buf[opt + 60..opt + 64].copy_from_slice(&(headers_size as u32).to_le_bytes()); // SizeOfHeaders
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem: CONSOLE
    buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    o += opt_size as usize;

    // Section header: .text
    let s = o;
    buf[s..s + 8].copy_from_slice(b".text\0\0\0");
    buf[s + 8..s + 12].copy_from_slice(&(code.len() as u32).to_le_bytes()); // VirtualSize
    buf[s + 12..s + 16].copy_from_slice(&PE_TEXT_RVA.to_le_bytes()); // VirtualAddress
    let raw_size = code.len().div_ceil(FILE_ALIGN) * FILE_ALIGN;
    buf[s + 16..s + 20].copy_from_slice(&(raw_size as u32).to_le_bytes()); // SizeOfRawData
    buf[s + 20..s + 24].copy_from_slice(&(headers_size as u32).to_le_bytes()); // PointerToRawData
    buf[s + 36..s + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // Characteristics

    // Section raw data.
    buf.resize(headers_size + raw_size, 0);
    buf[headers_size..headers_size + code.len()].copy_from_slice(code);
    buf
}
