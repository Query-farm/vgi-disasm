//! `capabilities(blob) -> TABLE(rule, attack_id, attack_name, severity, evidence)`
//! — the §B heuristic-only capability surface (import/string/anti-analysis →
//! MITRE ATT&CK). Explicitly **not** capa.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::arrow_io::const_input_bytes;
use crate::table::{commented, input_arg};
use disasm_core::Capability;

const EXECUTABLE_EXAMPLES: &str = r#"[
  {
    "description": "A PowerShell -EncodedCommand string flags T1059.001.",
    "sql": "SELECT attack_id FROM disasm.main.capabilities('powershell.exe -EncodedCommand ZQA='::BLOB) WHERE attack_id = 'T1059.001' LIMIT 1"
  }
]"#;

pub struct Capabilities;

fn output_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        commented(
            "rule",
            DataType::Utf8,
            "Short heuristic name, e.g. 'inject:CreateRemoteThread'.",
        ),
        commented(
            "attack_id",
            DataType::Utf8,
            "MITRE ATT&CK technique id, e.g. 'T1055.002'.",
        ),
        commented(
            "attack_name",
            DataType::Utf8,
            "MITRE ATT&CK technique name.",
        ),
        commented(
            "severity",
            DataType::Utf8,
            "Advisory severity: info, low, medium, or high.",
        ),
        commented(
            "evidence",
            DataType::Utf8,
            "The import name, string, or instruction that matched.",
        ),
    ]))
}

impl TableFunction for Capabilities {
    fn name(&self) -> &str {
        "capabilities"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Heuristic ATT&CK Capabilities",
            "Surface lightweight, ATT&CK-tagged capability indicators for malware triage from \
             three cheap signals: suspicious import names (e.g. VirtualAllocEx/WriteProcessMemory/\
             CreateRemoteThread → T1055 Process Injection), interesting strings (PowerShell -enc, \
             cmd.exe /c, autorun registry paths, VM-artifact names, ransom-note markers), and \
             anti-analysis instruction patterns (rdtsc/cpuid timing, int3 / int 0x2d). One row \
             per match with rule, attack_id, attack_name, severity (advisory only), and the \
             matched evidence. This is a deliberate heuristic over curated reference tables — it \
             is NOT a port of capa's rule engine. Input may be inline BLOB bytes or a VARCHAR path.",
            "Lightweight, [MITRE ATT&CK](https://attack.mitre.org/techniques/)-tagged capability \
             indicators for malware triage (`rule`, `attack_id`, `attack_name`, `severity`, \
             `evidence`), matched from three cheap signals — suspicious import names, interesting \
             strings, and anti-analysis instruction patterns. A deliberate heuristic over curated \
             reference tables; **not** a port of capa's rule engine.",
            &[
                "capabilities", "mitre", "att&ck", "attack", "heuristic", "malware", "triage",
                "process injection", "ransomware", "anti-debug", "anti-vm",
            ],
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n\
             |---|---|---|\n\
             | `rule` | VARCHAR | Short heuristic name. |\n\
             | `attack_id` | VARCHAR | ATT&CK technique id. |\n\
             | `attack_name` | VARCHAR | ATT&CK technique name. |\n\
             | `severity` | VARCHAR | info/low/medium/high. |\n\
             | `evidence` | VARCHAR | The matched import/string/instruction. |"
                .into(),
        ));
        tags.push(("vgi.executable_examples".into(), EXECUTABLE_EXAMPLES.into()));
        FunctionMetadata {
            description: "Heuristic capability indicators mapped to MITRE ATT&CK (rule, \
                          attack_id, attack_name, severity, evidence) — not capa"
                .into(),
            examples: vec![FunctionExample {
                sql: "SELECT rule, attack_id, evidence FROM \
                      disasm.main.capabilities('powershell.exe -EncodedCommand ZQA='::BLOB);"
                    .into(),
                description: "Surface ATT&CK-tagged capability indicators for a blob; pass a \
                              VARCHAR path to scan a file instead."
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
            Some(b) => disasm_core::capabilities(&b),
            None => Vec::new(),
        };
        Ok(Box::new(CapabilitiesProducer {
            schema: params.output_schema.clone(),
            rows: Some(rows),
        }))
    }
}

struct CapabilitiesProducer {
    schema: SchemaRef,
    rows: Option<Vec<Capability>>,
}

impl TableProducer for CapabilitiesProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        let Some(rows) = self.rows.take() else {
            return Ok(None);
        };

        let mut rule = StringBuilder::new();
        let mut attack_id = StringBuilder::new();
        let mut attack_name = StringBuilder::new();
        let mut severity = StringBuilder::new();
        let mut evidence = StringBuilder::new();

        for r in &rows {
            rule.append_value(&r.rule);
            attack_id.append_value(&r.attack_id);
            attack_name.append_value(&r.attack_name);
            severity.append_value(&r.severity);
            evidence.append_value(&r.evidence);
        }

        let cols: Vec<ArrayRef> = vec![
            Arc::new(rule.finish()),
            Arc::new(attack_id.finish()),
            Arc::new(attack_name.finish()),
            Arc::new(severity.finish()),
            Arc::new(evidence.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
