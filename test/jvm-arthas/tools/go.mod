// Test tooling for the Arthas stage-0 measurements. It is a separate module on purpose, so
// `go build ./...` and `go vet ./...` of the product module never see it.
module jvmarthastools

go 1.22
