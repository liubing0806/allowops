// Package reqctx carries the authenticated caller and the request audit
// metadata through context.Context. Packages that only need to read who is
// calling (job, mcp) depend on it instead of on the management API.
package reqctx
