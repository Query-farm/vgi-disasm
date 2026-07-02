//! `strings(blob [, min_len]) -> TABLE(offset, encoding, value)`.

use std::sync::Arc;

use arrow_array::builder::{StringBuilder, UInt64Builder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io::const_input_bytes;
use crate::table::{commented, input_arg};
use disasm_core::StringHit;

const EXECUTABLE_EXAMPLES: &str = r#"[
  {
    "description": "Extract ASCII strings (min length 4) from an inline blob.",
    "sql": "SELECT value FROM disasm.main.strings('hello world embedded text'::BLOB) WHERE encoding = 'ascii' ORDER BY \"offset\" LIMIT 1"
  }
]"#;

pub struct Strings;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "offset",
            DataType::UInt64,
            "File offset of the first byte of the string run.",
        ),
        commented(
            "encoding",
            DataType::Utf8,
            "Encoding of the run: ascii or utf16le.",
        ),
        commented(
            "value",
            DataType::Utf8,
            "The decoded printable string (truncated to a bounded length).",
        ),
    ]))
}

impl TableFunction for Strings {
    fn name(&self) -> &str {
        "strings"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Extract Printable Strings",
            "Classic strings-style extraction: runs of printable ASCII and UTF-16LE of length ≥ \
             min_len (default 4), each with its file offset and encoding (ascii or utf16le). \
             Feeds the string→indicator capability heuristics and is independently useful for \
             triage. Output count is bounded. Input may be inline BLOB bytes or a VARCHAR path.",
            "Classic `strings`-style extraction of printable ASCII and UTF-16LE runs of length ≥ \
             `min_len` (default 4), each with its file `offset` and `encoding`. Feeds the \
             string→indicator capability heuristics and is independently useful for triage; the \
             output count and per-string length are bounded.",
            &[
                "strings",
                "ascii",
                "utf16",
                "extract strings",
                "ioc",
                "triage",
                "printable",
                "offset",
            ],
            "Static Extraction",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n\
             |---|---|---|\n\
             | `offset` | UBIGINT | File offset of the run. |\n\
             | `encoding` | VARCHAR | ascii / utf16le. |\n\
             | `value` | VARCHAR | The decoded string. |"
                .into(),
        ));
        tags.push(("vgi.executable_examples".into(), EXECUTABLE_EXAMPLES.into()));
        FunctionMetadata {
            description: "Extract printable ASCII and UTF-16LE strings from a blob (offset, \
                          encoding, value)"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT \"offset\", encoding, value FROM \
                      disasm.main.strings('cmd.exe /c whoami'::BLOB, min_len := 6) \
                      ORDER BY \"offset\";"
                    .into(),
                description: "Extract printable strings (length ≥ 6) from a blob; pass a VARCHAR \
                              path to read a file instead."
                    .into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            input_arg(),
            ArgSpec::const_arg(
                "min_len",
                -1,
                "uint64",
                "Minimum run length to report (default 4). Shorter printable runs are ignored.",
            ),
        ]
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
        let min_len = params
            .arguments
            .named_i64("min_len")
            .filter(|v| *v >= 0)
            .map(|v| v as usize)
            .unwrap_or(4);
        let rows = match bytes {
            Some(b) => disasm_core::strings(&b, min_len),
            None => Vec::new(),
        };
        Ok(Box::new(StringsProducer {
            schema: params.output_schema.clone(),
            rows: Some(rows),
        }))
    }
}

struct StringsProducer {
    schema: SchemaRef,
    rows: Option<Vec<StringHit>>,
}

impl TableProducer for StringsProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        let Some(rows) = self.rows.take() else {
            return Ok(None);
        };

        let mut offset = UInt64Builder::new();
        let mut encoding = StringBuilder::new();
        let mut value = StringBuilder::new();

        for r in &rows {
            offset.append_value(r.offset);
            encoding.append_value(&r.encoding);
            value.append_value(&r.value);
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(offset.finish()),
            Arc::new(encoding.finish()),
            Arc::new(value.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
