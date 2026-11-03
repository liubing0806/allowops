// Package jvmarthas implements the jvm_arthas builtin: it loads Arthas into an
// allowlisted JVM, runs one fixed read-only command (level L1, no class is
// enhanced), turns the result into text and removes Arthas again.
//
// One call goes through these steps (each failure after the session record was
// written ends in the clean-up):
//
//  1. resolve the target and take the lock of the JVM (pid and start time);
//  2. recover session records that a dead call left behind;
//  3. check the JVM and the thresholds of builtin_config (no attach yet);
//  4. verify the five Arthas files in the target's mount namespace;
//  5. pick a port, write the session record, attach, wait for the port;
//  6. open an Arthas session, run the command, watch the JVM while it runs;
//  7. clean up with a time budget of its own: interrupt_job, close_session,
//     reset, stop; check that the port is closed and no arthas- thread is left;
//  8. delete the session record.
//
// The caller never supplies a pid, a path or a command text: it names a target
// of the signed configuration and the structured arguments of one command kind.
package jvmarthas
