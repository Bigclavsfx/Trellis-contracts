#![no_std]
// Compile the actual production modules without the unrelated broken root exports.
#[path = "../../../shared/src/errors.rs"]
pub mod errors;
#[path = "../../../shared/src/storage.rs"]
pub mod storage;
#[path = "../../../shared/src/history.rs"]
pub mod history;
#[path = "../../../shared/src/auth.rs"]
pub mod auth;
#[path = "../../../shared/src/evidence.rs"]
pub mod evidence;
#[path = "../../../shared/src/external_evidence.rs"]
pub mod external_evidence;
#[path = "../../../shared/src/jobs.rs"]
pub mod jobs;
#[cfg(test)]
#[path = "../../../shared/src/test_queue_backpressure.rs"]
mod test_queue_backpressure;
#[path = "../../../shared/src/events.rs"]
pub mod events;
#[path = "../../../shared/src/batch.rs"]
pub mod batch;
#[path = "../../../shared/src/error_taxonomy.rs"]
pub mod error_taxonomy;
