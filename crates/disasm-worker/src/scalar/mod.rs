//! Scalar functions exposed by the disasm worker, registered under `disasm.main`.

mod probe;
mod version;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(version::DisasmVersion);
    worker.register_scalar(probe::Format);
    worker.register_scalar(probe::Entrypoint);
}
