//! `sections(blob) -> TABLE(name, kind, vaddr, size, file_off, exec, entropy)`.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, Float64Builder, StringBuilder, UInt64Builder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io::const_input_bytes;
use crate::table::{commented, input_arg};
use disasm_core::Section;

const EXECUTABLE_EXAMPLES: &str = r#"[
  {
    "description": "A raw (non-container) blob has no sections.",
    "sql": "SELECT count(*) AS n FROM disasm.main.sections('not a binary')"
  }
]"#;

pub struct Sections;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented("name", DataType::Utf8, "Section/segment name, e.g. '.text' or '__TEXT,__text'."),
        commented("kind", DataType::Utf8, "Section class: code, data, rodata, bss, debug, or other."),
        commented("vaddr", DataType::UInt64, "Virtual address of the section (absolute; PE adds image base)."),
        commented("size", DataType::UInt64, "Declared section size in bytes (virtual size)."),
        commented("file_off", DataType::UInt64, "File offset of the section's bytes."),
        commented("exec", DataType::Boolean, "True if the section is executable (part of the disassemble(section:='auto') set)."),
        commented("entropy", DataType::Float64, "Shannon entropy (bits/byte, 0..8) over the section's file bytes; high values flag packing/encryption."),
    ]))
}

impl TableFunction for Sections {
    fn name(&self) -> &str {
        "sections"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Enumerate Sections / Segments",
            "Enumerate the sections/segments of a PE/ELF/Mach-O binary via goblin: one row per \
             section with name, kind (code/data/rodata/bss/debug/other), vaddr, size, file_off, \
             an exec flag (the executable sections disassemble(section:='auto') sweeps), and \
             Shannon entropy over the section bytes (a packed/encrypted-section flag). A raw blob \
             yields zero rows. Input may be inline BLOB bytes or a VARCHAR path.",
            "Enumerate the sections/segments of a [PE](https://learn.microsoft.com/windows/win32/debug/pe-format) \
             / [ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) / Mach-O binary (`name`, \
             `kind`, `vaddr`, `size`, `file_off`, `exec`, `entropy`). `exec` marks the executable \
             sections that `disassemble(section := 'auto')` sweeps; high `entropy` (near 8 \
             bits/byte) flags a packed or encrypted section. A raw (non-container) blob yields zero \
             rows.",
            &[
                "sections",
                "segments",
                "pe",
                "elf",
                "macho",
                "entropy",
                "packed",
                "executable",
                "vaddr",
                "code section",
            ],
            "Static Extraction",
        );
        tags.push((
            "vgi.result_columns_schema".into(),
            crate::meta::result_columns_schema_json(&[
                ("name", "VARCHAR", "Section/segment name, e.g. '.text' or '__TEXT,__text'."),
                ("kind", "VARCHAR", "Section class: code, data, rodata, bss, debug, or other."),
                ("vaddr", "UBIGINT", "Virtual address of the section (absolute; PE adds image base)."),
                ("size", "UBIGINT", "Declared section size in bytes (virtual size)."),
                ("file_off", "UBIGINT", "File offset of the section's bytes."),
                ("exec", "BOOLEAN", "True if the section is executable (the disassemble(section := 'auto') set)."),
                ("entropy", "DOUBLE", "Shannon entropy (bits/byte, 0..8) over the section's file bytes; high values flag packing/encryption."),
            ]),
        ));
        tags.push(("vgi.executable_examples".into(), EXECUTABLE_EXAMPLES.into()));
        FunctionMetadata {
            description: "Enumerate the sections/segments of a binary (name, kind, vaddr, size, \
                          file_off, exec, entropy)"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT count(*) AS n FROM disasm.main.sections('not a binary'::BLOB);".into(),
                description: "Count the sections of a blob (a raw blob has none). Pass a real \
                              binary as inline BLOB bytes or a VARCHAR path to enumerate them."
                    .into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![input_arg()]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let bytes = const_input_bytes(
            params.arguments.const_bytes(0),
            params.arguments.const_str(0),
        );
        let rows = match bytes {
            Some(b) => disasm_core::sections(&b),
            None => Vec::new(),
        };
        Ok(Box::new(SectionsProducer {
            schema: params.output_schema.clone(),
            rows: Some(rows),
        }))
    }
}

struct SectionsProducer {
    schema: SchemaRef,
    rows: Option<Vec<Section>>,
}

impl TableProducer for SectionsProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        let Some(rows) = self.rows.take() else {
            return Ok(None);
        };

        let mut name = StringBuilder::new();
        let mut kind = StringBuilder::new();
        let mut vaddr = UInt64Builder::new();
        let mut size = UInt64Builder::new();
        let mut file_off = UInt64Builder::new();
        let mut exec = BooleanBuilder::new();
        let mut entropy = Float64Builder::new();

        for r in &rows {
            name.append_value(&r.name);
            kind.append_value(&r.kind);
            vaddr.append_value(r.vaddr);
            size.append_value(r.size);
            file_off.append_value(r.file_off);
            exec.append_value(r.exec);
            entropy.append_value(r.entropy);
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(name.finish()),
            Arc::new(kind.finish()),
            Arc::new(vaddr.finish()),
            Arc::new(size.finish()),
            Arc::new(file_off.finish()),
            Arc::new(exec.finish()),
            Arc::new(entropy.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
