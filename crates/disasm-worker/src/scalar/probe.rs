//! `format(blob) -> STRUCT(container, arch, mode, bits, endian, entry)` and
//! `entrypoint(blob) -> STRUCT(arch, mode, vaddr, file_off, section)`.
//!
//! Both are cheap header-only probes (no disassembly). Input may be inline BLOB
//! bytes or a VARCHAR path. A NULL cell yields a NULL struct; a raw/unrecognized
//! blob yields a populated `format` struct with `container='raw'` and NULL
//! detail fields, and an all-NULL-field `entrypoint` struct.

use std::sync::Arc;

use arrow_array::builder::{StringBuilder, UInt64Builder, UInt8Builder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_buffer::NullBuffer;
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::{entrypoint_struct_fields, format_struct_fields, input_bytes};

/// `format(blob)` — container probe without disassembling.
pub struct Format;

impl ScalarFunction for Format {
    fn name(&self) -> &str {
        "format"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Probe a blob's container/arch without disassembling: \
                          STRUCT(container, arch, mode, bits, endian, entry)"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT disasm.main.format(from_hex('7f454c46'));".into(),
                description: "Probe the ELF magic and report the container type.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Probe Binary Format",
                "Cheaply probe a blob's container and architecture WITHOUT disassembling: returns \
                 a STRUCT(container, arch, mode, bits, endian, entry). container is one of pe, \
                 elf, macho, fat-macho, or raw. The fast pre-filter for 'is this even a binary I \
                 can disassemble' across a large scan. Input may be inline BLOB bytes or a VARCHAR \
                 path. A raw/unrecognized blob returns container='raw' with NULL detail fields.",
                "Probe a blob's container/arch without disassembling — \
                 `STRUCT(container, arch, mode, bits, endian, entry)`.",
                &[
                    "format",
                    "container",
                    "probe",
                    "magic",
                    "pe",
                    "elf",
                    "macho",
                    "fat",
                    "arch detect",
                    "bitness",
                    "endianness",
                    "is binary",
                ],
                "Container Probe",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "The binary or shellcode to probe: the raw bytes supplied inline, or a filesystem \
             path to the file to read. Only the container header is read; the bytes are never \
             executed.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(
            format_struct_fields(),
        )))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();

        let mut container = StringBuilder::new();
        let mut arch = StringBuilder::new();
        let mut mode = StringBuilder::new();
        let mut bits = UInt8Builder::new();
        let mut endian = StringBuilder::new();
        let mut entry = UInt64Builder::new();
        let mut valid = Vec::with_capacity(rows);

        for i in 0..rows {
            match input_bytes(col, i)? {
                Some(bytes) => {
                    let p = disasm_core::probe(&bytes);
                    container.append_value(&p.container);
                    arch.append_option(p.arch.as_deref());
                    mode.append_option(p.mode.as_deref());
                    bits.append_option(p.bits);
                    endian.append_option(p.endian.as_deref());
                    entry.append_option(p.entry);
                    valid.push(true);
                }
                None => {
                    container.append_null();
                    arch.append_null();
                    mode.append_null();
                    bits.append_null();
                    endian.append_null();
                    entry.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(container.finish()),
            Arc::new(arch.finish()),
            Arc::new(mode.finish()),
            Arc::new(bits.finish()),
            Arc::new(endian.finish()),
            Arc::new(entry.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(
            format_struct_fields(),
            arrays,
            Some(NullBuffer::from(valid)),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// `entrypoint(blob)` — resolved entry point.
pub struct Entrypoint;

impl ScalarFunction for Entrypoint {
    fn name(&self) -> &str {
        "entrypoint"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "The container entry point and resolved (arch, mode): \
                          STRUCT(arch, mode, vaddr, file_off, section)"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT (disasm.main.entrypoint('not a binary'::BLOB)).arch AS arch;".into(),
                description: "Resolve a blob's entry point; a raw blob yields NULL fields. Pass a \
                              real binary as inline BLOB bytes or a VARCHAR path."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Resolve Entry Point",
                "Resolve the container entry point and the (arch, mode) it implies: returns a \
                 STRUCT(arch, mode, vaddr, file_off, section). vaddr is the entry virtual address, \
                 file_off its file offset, and section the section that contains it. For a Mach-O \
                 fat binary the primary (first) slice is reported. A raw blob returns NULL struct \
                 fields. Input may be inline BLOB bytes or a VARCHAR path.",
                "Resolve a binary's entry point — \
                 `STRUCT(arch, mode, vaddr, file_off, section)`. NULL fields for a raw blob.",
                &[
                    "entrypoint",
                    "entry point",
                    "entry",
                    "start address",
                    "vaddr",
                    "arch",
                    "mode",
                    "section",
                ],
                "Container Probe",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::any_column(
            "blob",
            0,
            "The binary to resolve the entry point of: the raw bytes supplied inline, or a \
             filesystem path to the file to read. Only headers are read; the bytes are never \
             executed.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(
            entrypoint_struct_fields(),
        )))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let rows = batch.num_rows();

        let mut arch = StringBuilder::new();
        let mut mode = StringBuilder::new();
        let mut vaddr = UInt64Builder::new();
        let mut file_off = UInt64Builder::new();
        let mut section = StringBuilder::new();
        let mut valid = Vec::with_capacity(rows);

        for i in 0..rows {
            match input_bytes(col, i)? {
                Some(bytes) => {
                    let e = disasm_core::entrypoint(&bytes);
                    arch.append_option(e.arch.as_deref());
                    mode.append_option(e.mode.as_deref());
                    vaddr.append_option(e.vaddr);
                    file_off.append_option(e.file_off);
                    section.append_option(e.section.as_deref());
                    valid.push(true);
                }
                None => {
                    arch.append_null();
                    mode.append_null();
                    vaddr.append_null();
                    file_off.append_null();
                    section.append_null();
                    valid.push(false);
                }
            }
        }

        let arrays: Vec<ArrayRef> = vec![
            Arc::new(arch.finish()),
            Arc::new(mode.finish()),
            Arc::new(vaddr.finish()),
            Arc::new(file_off.finish()),
            Arc::new(section.finish()),
        ];
        let out: ArrayRef = Arc::new(StructArray::new(
            entrypoint_struct_fields(),
            arrays,
            Some(NullBuffer::from(valid)),
        ));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::run_scalar;
    use arrow_array::cast::AsArray;
    use arrow_array::Array;
    use vgi::arguments::Arguments;

    #[test]
    fn format_raw_blob_reports_raw() {
        let out = run_scalar(&Format, &[Some(b"not a binary")], Arguments::default()).unwrap();
        let s = out.as_struct();
        let container = s.column(0).as_string::<i32>();
        assert_eq!(container.value(0), "raw");
        assert!(s.column(1).is_null(0)); // arch NULL
    }

    #[test]
    fn format_null_input_null_struct() {
        let out = run_scalar(&Format, &[None], Arguments::default()).unwrap();
        assert!(out.is_null(0));
    }

    #[test]
    fn entrypoint_raw_blob_null_fields() {
        let out = run_scalar(&Entrypoint, &[Some(b"xyz")], Arguments::default()).unwrap();
        let s = out.as_struct();
        assert!(!out.is_null(0)); // struct present
        assert!(s.column(0).is_null(0)); // arch NULL
        assert!(s.column(2).is_null(0)); // vaddr NULL
    }
}
