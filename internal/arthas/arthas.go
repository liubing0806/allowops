// Package arthas drives an Arthas 4.3.5 server that has been loaded into a
// target JVM: it builds the agent argument, talks to the HTTP API, generates
// the fixed set of read-only commands, turns the JSON results into plain text
// and runs the clean-up sequence.
//
// The package neither attaches to a JVM nor chooses a network namespace. The
// caller supplies a Dial function and receives raw connections.
//
// A call goes through these steps:
//
//	cmd, err := Build(req, policy)            // validate the request first; cmd.Name is the command to enable
//	cfg := AgentConfig{..., Enabled: []string{cmd.Name}}
//	arg, err := cfg.Argument()                // attach: "load instrument false <arg>"
//	c, err := NewClient(Config{Dial: dial, Password: cfg.Password})
//	sid, err := c.InitSession(ctx)
//	resp, err := c.Exec(ctx, sid, cmd)        // *StateError for INTERRUPTED, FAILED, REFUSED
//	text, err := Render(cmd.Kind, resp)       // *CommandError when the command reported a failure
//	res := c.Cleanup(ctx, sid, CleanupOptions{}) // after every call, also after an error
//
// After Cleanup the caller checks that the port is closed and that no arthas-
// thread is left in the target.
package arthas

// Version is the only Arthas release the command names, the response formats
// and the agent argument rules in this package were checked against.
const Version = "4.3.5"
