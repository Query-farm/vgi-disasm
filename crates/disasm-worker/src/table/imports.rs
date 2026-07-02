//! `imports(blob) -> TABLE(library, name, ordinal, kind)`.

use std::sync::Arc;

use arrow_array::builder::{Int32Builder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io::const_input_bytes;
use crate::table::{commented, input_arg};
use disasm_core::Import;

const EXECUTABLE_EXAMPLES: &str = r#"[
  {
    "description": "A raw (non-container) blob has no imports.",
    "sql": "SELECT count(*) AS n FROM disasm.main.imports('not a binary')"
  }
]"#;

pub struct Imports;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented("library", DataType::Utf8, "Importing library/DLL/dylib name, or NULL when the container does not attribute the symbol to one (typical for ELF)."),
        commented("name", DataType::Utf8, "Imported symbol name, or NULL for an ordinal-only PE import."),
        commented("ordinal", DataType::Int32, "Import ordinal (PE), or NULL."),
        commented("kind", DataType::Utf8, "Import kind: named, ordinal, or delayed."),
    ]))
}

impl TableFunction for Imports {
    fn name(&self) -> &str {
        "imports"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Enumerate Imported Symbols",
            "Enumerate the imported symbols of a PE/ELF/Mach-O binary: PE import directory \
             (including ordinal-only imports, name NULL then), ELF dynamic-symbol imports, and \
             Mach-O bind/lazy imports. One row per import with library, name, ordinal, and kind \
             (named, ordinal, delayed). This is the input to the import-name capability \
             heuristics and a join key to vgi-pe. A raw blob yields zero rows. Input may be \
             inline BLOB bytes or a VARCHAR path.",
            "Enumerate a binary's imported symbols (`library`, `name`, `ordinal`, `kind`) across \
             PE (import directory, including ordinal-only entries where `name` is NULL), ELF \
             (dynamic-symbol imports), and Mach-O (bind/lazy). The input to the import-name \
             capability heuristics and a join key to `vgi-pe`. A raw blob yields zero rows.",
            &[
                "imports",
                "iat",
                "import table",
                "symbols",
                "dll",
                "dylib",
                "api",
                "malware",
                "pe",
                "elf",
                "macho",
            ],
            "Static Extraction",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n\
             |---|---|---|\n\
             | `library` | VARCHAR | Importing library/DLL, or NULL. |\n\
             | `name` | VARCHAR | Symbol name, or NULL (ordinal-only). |\n\
             | `ordinal` | INTEGER | Import ordinal, or NULL. |\n\
             | `kind` | VARCHAR | named / ordinal / delayed. |"
                .into(),
        ));
        tags.push(("vgi.executable_examples".into(), EXECUTABLE_EXAMPLES.into()));
        FunctionMetadata {
            description:
                "Enumerate the imported symbols of a binary (library, name, ordinal, kind)".into(),
            examples: vec![FunctionExample {
                sql: "SELECT count(*) AS n FROM disasm.main.imports('not a binary'::BLOB);".into(),
                description: "Count the imported symbols of a blob (a raw blob has none). Pass a \
                              real binary as inline BLOB bytes or a VARCHAR path to list them."
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
            Some(b) => disasm_core::imports(&b),
            None => Vec::new(),
        };
        Ok(Box::new(ImportsProducer {
            schema: params.output_schema.clone(),
            rows: Some(rows),
        }))
    }
}

struct ImportsProducer {
    schema: SchemaRef,
    rows: Option<Vec<Import>>,
}

impl TableProducer for ImportsProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        let Some(rows) = self.rows.take() else {
            return Ok(None);
        };

        let mut library = StringBuilder::new();
        let mut name = StringBuilder::new();
        let mut ordinal = Int32Builder::new();
        let mut kind = StringBuilder::new();

        for r in &rows {
            library.append_option(r.library.as_deref());
            name.append_option(r.name.as_deref());
            ordinal.append_option(r.ordinal);
            kind.append_value(&r.kind);
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(library.finish()),
            Arc::new(name.finish()),
            Arc::new(ordinal.finish()),
            Arc::new(kind.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
