//! Driving a debugger from the analysis: GDB, or LLDB through `lldb-mi`,
//! spoken to over the GDB machine interface, with the program's addresses
//! read back to the image's so the static listing can follow the program
//! counter.
//!
//! [`mi`] parses the interface's records; [`session`] drives a debugger
//! over a [`Transport`], learns the slide between the image and the running
//! program, and keeps what the debugger says as [`Event`]s; [`fake`] is a
//! scripted debugger for tests.

pub mod fake;
pub mod mi;
pub mod session;

pub use session::{Debugger, Event, Frame, ProcessTransport, Session, State, Transport};
