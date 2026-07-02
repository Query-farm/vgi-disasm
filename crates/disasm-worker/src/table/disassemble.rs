//! `disassemble(blob [, arch, mode, base, section]) -> TABLE(address, size,
//! bytes, mnemonic, op_str, groups)` — the core linear-sweep instruction relation.

use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, ListBuilder, StringBuilder, UInt64Builder, UInt8Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io::const_input_bytes;
use crate::table::{commented, input_arg};
use disasm_core::Insn;

const EXECUTABLE_EXAMPLES: &str = r#"[
  {
    "description": "Disassemble x64 shellcode at an explicit base (0x1000); list its return sites.",
    "sql": "SELECT address, mnemonic, op_str FROM disasm.main.disassemble(from_hex('554889e5c3'), arch := 'x86', mode := 'x64', base := 4096) WHERE list_contains(groups, 'ret')"
  },
  {
    "description": "Count decoded instructions in a raw x64 nop sled.",
    "sql": "SELECT count(*) AS n FROM disasm.main.disassemble(from_hex('90909090'), arch := 'x86', mode := 'x64')"
  }
]"#;

pub struct Disassemble;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented("address", DataType::UInt64, "Absolute virtual address of the instruction (base + offset)."),
        commented("size", DataType::UInt8, "Instruction length in bytes (0 only for the synthetic error row)."),
        commented("bytes", DataType::Binary, "The raw machine bytes of this instruction."),
        commented("mnemonic", DataType::Utf8, "Instruction mnemonic, e.g. 'mov', 'call', 'bl'; '.byte' for an undecodable byte; '(error)' for a diagnostic row."),
        commented("op_str", DataType::Utf8, "Operand text, e.g. 'rax, qword ptr [rip + 0x2f1a]'."),
        commented(
            "groups",
            DataType::List(Arc::new(arrow_schema::Field::new("item", DataType::Utf8, true))),
            "Normalized instruction groups (call, jump, ret, int, privileged, branch_relative, fpu, sse, vm) for SQL filtering.",
        ),
    ]))
}

impl TableFunction for Disassemble {
    fn name(&self) -> &str {
        "disassemble"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Disassemble Into Instruction Rows",
            "Disassemble the executable sections of a PE/ELF/Mach-O binary — or a raw shellcode \
             blob — into one row per machine instruction via Capstone. Arch/mode auto-detect from \
             the container, or pass arch (x86, arm, arm64, mips, ppc, sysz, riscv) and mode (x16, \
             x32, x64, arm, thumb, big, little) explicitly (required for raw blobs). base seeds \
             the address column and makes branch targets print absolute; section selects auto \
             (every executable section), all (the whole blob as raw bytes), or a section name. \
             Each row carries address, size, bytes, mnemonic, op_str, and a normalized groups \
             LIST<VARCHAR> (call/jump/ret/int/privileged/branch_relative/fpu/sse/vm). Output is \
             address-ordered and bounded; undecodable bytes become '.byte' rows so the sweep \
             never stalls. The input is statically decoded, never executed.",
            "Disassemble a binary or shellcode into instruction rows (`address`, `size`, `bytes`, \
             `mnemonic`, `op_str`, `groups`) via [Capstone](https://www.capstone-engine.org/). \
             Arch/mode auto-detect from a PE/ELF/Mach-O container, or pass `arch` / `mode` \
             explicitly (required for raw shellcode). v1 uses a **linear sweep** from the start of \
             each selected section — simple and deterministic, but it can mis-decode data \
             interleaved in code; undecodable bytes become `.byte` rows and the sweep resumes, so \
             it never stalls. Supported arches: x86 (16/32/64), arm, arm64, mips, ppc, sysz, \
             riscv.",
            &[
                "disassemble",
                "disassembly",
                "capstone",
                "instructions",
                "opcodes",
                "mnemonic",
                "shellcode",
                "malware",
                "triage",
                "x86",
                "arm",
                "linear sweep",
            ],
            "Disassembly",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n\
             |---|---|---|\n\
             | `address` | UBIGINT | Absolute VA (base + offset). |\n\
             | `size` | UTINYINT | Instruction length in bytes. |\n\
             | `bytes` | BLOB | Raw machine bytes of the instruction. |\n\
             | `mnemonic` | VARCHAR | Mnemonic, e.g. `mov`, `call`, `bl`. |\n\
             | `op_str` | VARCHAR | Operand text. |\n\
             | `groups` | VARCHAR[] | Normalized instruction groups for SQL filtering. |"
                .into(),
        ));
        tags.push(("vgi.executable_examples".into(), EXECUTABLE_EXAMPLES.into()));
        FunctionMetadata {
            description: "Disassemble a binary or shellcode blob into one row per machine \
                          instruction (address, size, bytes, mnemonic, op_str, groups)"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT address, mnemonic, op_str FROM \
                      disasm.main.disassemble(from_hex('554889e5c3'), arch := 'x86', mode := 'x64');"
                    .into(),
                description: "Disassemble a tiny x64 shellcode blob.".into(),
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
                "arch",
                -1,
                "varchar",
                "Override container detection or supply the arch for raw bytes: x86, arm, arm64, \
                 mips, ppc, sysz, or riscv. Required for a raw blob (no container to read).",
            ),
            ArgSpec::const_arg(
                "mode",
                -1,
                "varchar",
                "Decode mode: x16, x32, x64 (x86 width), arm or thumb (32-bit ARM), or big/little \
                 (endianness for the other arches).",
            ),
            ArgSpec::const_arg(
                "base",
                -1,
                "uint64",
                "Virtual/load address of the first byte (default = the section's VA, or 0 for a \
                 raw blob), so branch-relative operands print absolute targets.",
            ),
            ArgSpec::const_arg(
                "section",
                -1,
                "varchar",
                "What to sweep: 'auto' (every executable section, the default), 'all' (the whole \
                 blob as raw bytes at base), or a section name such as '.text' or '__text'.",
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
        let arch = params.arguments.named_str("arch");
        let mode = params.arguments.named_str("mode");
        let base = params.arguments.named_i64("base").map(|v| v as u64);
        let section = params
            .arguments
            .named_str("section")
            .unwrap_or_else(|| "auto".to_string());

        let rows = match bytes {
            Some(b) => {
                disasm_core::disassemble(&b, arch.as_deref(), mode.as_deref(), base, &section)
            }
            None => Vec::new(),
        };
        Ok(Box::new(DisasmProducer {
            schema: params.output_schema.clone(),
            rows: Some(rows),
        }))
    }
}

struct DisasmProducer {
    schema: SchemaRef,
    rows: Option<Vec<Insn>>,
}

impl TableProducer for DisasmProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        let Some(rows) = self.rows.take() else {
            return Ok(None);
        };

        let mut address = UInt64Builder::new();
        let mut size = UInt8Builder::new();
        let mut bytes = BinaryBuilder::new();
        let mut mnemonic = StringBuilder::new();
        let mut op_str = StringBuilder::new();
        let mut groups = ListBuilder::new(StringBuilder::new());

        for r in &rows {
            address.append_value(r.address);
            size.append_value(r.size);
            bytes.append_value(&r.bytes);
            mnemonic.append_value(&r.mnemonic);
            op_str.append_value(&r.op_str);
            for g in &r.groups {
                groups.values().append_value(g);
            }
            groups.append(true);
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(address.finish()),
            Arc::new(size.finish()),
            Arc::new(bytes.finish()),
            Arc::new(mnemonic.finish()),
            Arc::new(op_str.finish()),
            Arc::new(groups.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
