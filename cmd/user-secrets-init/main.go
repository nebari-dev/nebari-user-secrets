// Command user-secrets-init is the init container binary that materialises
// user secrets into a pod. It is a stub until Slice 7: it only prints usage.
package main

import (
	"fmt"
	"io"
	"os"
)

const usage = "usage: user-secrets-init (not implemented yet; arrives in Slice 7)"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

// run prints usage to stdout and returns exit code 0 for any arguments,
// so the stub image can be smoke-tested with or without --help.
func run(_ []string, stdout io.Writer) int {
	_, _ = fmt.Fprintln(stdout, usage)
	return 0
}
