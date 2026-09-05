//! Host-only test oracle for the embedded Kindling VM: an independent
//! tree-walking reference interpreter and a deterministic random program
//! generator. Two independent evaluators agreeing on the same program is the
//! machine-checkable oracle behind the differential correctness gate.

pub mod gen;
pub mod interp;
