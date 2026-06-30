//! Imported-symbol enumeration across PE / ELF / Mach-O.
//!
//! Backs the `imports()` table function and feeds the import-name capability
//! heuristics. PE import directory (named + ordinal-only), ELF dynamic-symbol
//! imports, and Mach-O bind/lazy imports are normalized into a single shape.
//! Wrapped against malformed input (zero rows, never a panic) and bounded to
//! [`MAX_IMPORTS`].

use goblin::Object;

use crate::limits::MAX_IMPORTS;

/// One imported symbol.
#[derive(Debug, Clone)]
pub struct Import {
    /// Importing library / DLL / dylib name, or `None` when the container does
    /// not attribute the symbol to one (typical for ELF).
    pub library: Option<String>,
    /// Symbol name, or `None` for an ordinal-only PE import.
    pub name: Option<String>,
    /// Import ordinal (PE), or `None`.
    pub ordinal: Option<i32>,
    /// `named | ordinal | delayed`.
    pub kind: String,
}

/// Enumerate the imported symbols of `bytes`. Empty for a raw blob or parse
/// failure; bounded to [`MAX_IMPORTS`].
pub fn imports(bytes: &[u8]) -> Vec<Import> {
    parse(bytes).unwrap_or_default()
}

fn parse(bytes: &[u8]) -> Option<Vec<Import>> {
    let obj = Object::parse(bytes).ok()?;
    let mut out = Vec::new();
    match obj {
        Object::Elf(elf) => elf_imports(&elf, &mut out),
        Object::PE(pe) => pe_imports(&pe, &mut out),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => mach_imports(&macho, &mut out),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            if let Some(Ok(goblin::mach::SingleArch::MachO(macho))) = fat.into_iter().next() {
                mach_imports(&macho, &mut out);
            }
        }
        _ => {}
    }
    out.truncate(MAX_IMPORTS);
    Some(out)
}

fn elf_imports(elf: &goblin::elf::Elf, out: &mut Vec<Import>) {
    for sym in elf.dynsyms.iter() {
        if out.len() >= MAX_IMPORTS {
            break;
        }
        if !sym.is_import() {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.push(Import {
            library: None,
            name: Some(name.to_string()),
            ordinal: None,
            kind: "named".to_string(),
        });
    }
}

fn pe_imports(pe: &goblin::pe::PE, out: &mut Vec<Import>) {
    for imp in &pe.imports {
        if out.len() >= MAX_IMPORTS {
            break;
        }
        let name = imp.name.to_string();
        let dll = imp.dll.to_string();
        let library = (!dll.is_empty()).then_some(dll);
        let ord = imp.ordinal;
        // Ordinal-only imports surface as an empty / synthesized name.
        let is_ordinal = name.is_empty() || name.starts_with("ORDINAL");
        if is_ordinal {
            out.push(Import {
                library,
                name: None,
                ordinal: Some(ord as i32),
                kind: "ordinal".to_string(),
            });
        } else {
            out.push(Import {
                library,
                name: Some(name),
                ordinal: Some(ord as i32),
                kind: "named".to_string(),
            });
        }
    }
}

fn mach_imports(macho: &goblin::mach::MachO, out: &mut Vec<Import>) {
    let Ok(imps) = macho.imports() else { return };
    for imp in imps {
        if out.len() >= MAX_IMPORTS {
            break;
        }
        let dylib = imp.dylib.to_string();
        out.push(Import {
            library: (!dylib.is_empty()).then_some(dylib),
            name: Some(imp.name.to_string()),
            ordinal: None,
            kind: if imp.is_lazy { "delayed" } else { "named" }.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_blob_no_imports() {
        assert!(imports(b"not a binary").is_empty());
    }
}
