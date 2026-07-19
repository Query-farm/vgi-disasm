//! Arrow boundary helpers shared across the scalar/table adapters: resolving an
//! input cell (BLOB bytes *or* a VARCHAR path to open) to raw bytes, the shared
//! `groups LIST<VARCHAR>` and struct field types, and an in-process test harness.
//!
//! Keeping path-vs-bytes marshalling here means every function accepts the same
//! two input shapes — `disassemble(b.content)` (inline bytes) and
//! `disassemble('sample.bin')` (a path) — without duplicating the logic.

use std::borrow::Cow;

use arrow_array::ArrayRef;
use arrow_schema::{DataType, Field, Fields};
use vgi_rpc::{Result, RpcError};

use disasm_core::limits::MAX_SCAN_BYTES;

/// Resolve an input cell at `row` to raw container/shellcode bytes.
///
/// * **BLOB** (`Binary`/`LargeBinary`) — the bytes inline; or
/// * **VARCHAR** (`Utf8`/`LargeUtf8`) — a filesystem **path** to read (bounded).
///
/// `None` for a NULL cell or an unreadable/oversized path (treated as "no usable
/// input" — the caller surfaces that as empty/diagnostic output, never a panic).
/// Errors only if the column is neither binary nor string typed.
pub fn input_bytes(col: &ArrayRef, row: usize) -> Result<Option<Cow<'_, [u8]>>> {
    use arrow_array::cast::AsArray;
    use arrow_array::Array;

    if col.is_null(row) {
        return Ok(None);
    }
    Ok(match col.data_type() {
        DataType::Binary => Some(Cow::Borrowed(col.as_binary::<i32>().value(row))),
        DataType::LargeBinary => Some(Cow::Borrowed(col.as_binary::<i64>().value(row))),
        DataType::Utf8 => read_path(col.as_string::<i32>().value(row)),
        DataType::LargeUtf8 => read_path(col.as_string::<i64>().value(row)),
        other => {
            return Err(RpcError::value_error(format!(
                "input must be a BLOB (file bytes) or VARCHAR (path), got {other:?}"
            )))
        }
    })
}

/// Read a file from `path`, bounded to [`MAX_SCAN_BYTES`]. Any error (missing,
/// permission, too large) yields `None` rather than propagating.
fn read_path(path: &str) -> Option<Cow<'static, [u8]>> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() as usize > MAX_SCAN_BYTES {
        return None;
    }
    std::fs::read(path).ok().map(Cow::Owned)
}

/// Resolve a *constant* (bind-time) table-function argument — a BLOB constant
/// or a VARCHAR path constant — to raw bytes. `None` (→ no rows) when neither
/// yields usable bytes.
pub fn const_input_bytes(bytes_arg: Option<Vec<u8>>, str_arg: Option<String>) -> Option<Vec<u8>> {
    if let Some(b) = bytes_arg {
        return Some(b);
    }
    read_path(&str_arg?).map(|c| c.into_owned())
}

/// `STRUCT(arch, mode, vaddr, file_off, section)` — the `entrypoint()` return.
pub fn entrypoint_struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("arch", DataType::Utf8, true),
        Field::new("mode", DataType::Utf8, true),
        Field::new("vaddr", DataType::UInt64, true),
        Field::new("file_off", DataType::UInt64, true),
        Field::new("section", DataType::Utf8, true),
    ])
}

/// `STRUCT(container, arch, mode, bits, endian, entry)` — the `format()` return.
pub fn format_struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("container", DataType::Utf8, true),
        Field::new("arch", DataType::Utf8, true),
        Field::new("mode", DataType::Utf8, true),
        Field::new("bits", DataType::UInt8, true),
        Field::new("endian", DataType::Utf8, true),
        Field::new("entry", DataType::UInt64, true),
    ])
}

/// Test-only helpers: build a one-column BLOB input `RecordBatch`, run a scalar
/// `on_bind` + `process`, and inspect the result — all in-process, no RPC/IPC.
#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;

    use arrow_array::builder::BinaryBuilder;
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{Field, Schema, SchemaRef};
    use vgi::arguments::Arguments;
    use vgi::{BindParams, ProcessParams, ScalarFunction};
    use vgi_rpc::Result;

    /// A single-column `Binary` (BLOB) input batch. `None` entries become NULLs.
    pub fn blob_batch(rows: &[Option<&[u8]>]) -> RecordBatch {
        let mut b = BinaryBuilder::new();
        for r in rows {
            match r {
                Some(bytes) => b.append_value(bytes),
                None => b.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(b.finish());
        let schema = Arc::new(Schema::new(vec![Field::new(
            "blob",
            arr.data_type().clone(),
            true,
        )]));
        RecordBatch::try_new(schema, vec![arr]).unwrap()
    }

    /// Build a `ProcessParams` carrying the given output schema and arguments.
    pub fn process_params(output_schema: SchemaRef, arguments: Arguments) -> ProcessParams {
        ProcessParams {
            substream_id: None,
            if_none_match: None,
            if_modified_since: None,
            output_schema,
            input_schema: None,
            execution_id: Vec::new(),
            init_opaque_data: Vec::new(),
            arguments,
            settings: Default::default(),
            secrets: Default::default(),
            auth_principal: None,
            projection_ids: None,
            pushdown_filters: None,
            join_keys: Vec::new(),
            storage: None,
            order_by_column: None,
            order_by_direction: None,
            order_by_null_order: None,
            order_by_limit: None,
            tablesample_percentage: None,
            tablesample_seed: None,
            attach_opaque_data: None,
            at_unit: None,
            at_value: None,
            copy_from: None,
        }
    }

    /// Run a scalar function over a `Binary` input batch, returning the single
    /// result column.
    pub fn run_scalar<F: ScalarFunction>(
        f: &F,
        rows: &[Option<&[u8]>],
        arguments: Arguments,
    ) -> Result<ArrayRef> {
        let batch = blob_batch(rows);
        let bind = BindParams {
            input_schema: Some(batch.schema()),
            arguments: arguments.clone(),
            ..Default::default()
        };
        let bound = f.on_bind(&bind)?;
        let params = process_params(bound.output_schema.clone(), arguments);
        let out = f.process(&params, &batch)?;
        Ok(out.column(0).clone())
    }
}
