// Command user-secrets is the nebari-user-secrets service binary: the serve
// subcommand runs the service and the admin subcommands manage master keys.
package main

import (
	"fmt"
	"io"
	"os"
)

const usage = "usage: user-secrets serve --config <file>\n" +
	"       user-secrets admin rotate-kek|retire-kek <id>|rotate-dek [--owner <sub>] " +
	"--actor <name> [--namespace <ns>]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches the subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		_, _ = fmt.Fprintln(stdout, usage)
		return 0
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "admin":
		return runAdmin(args[1:])
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n%s\n", args[0], usage)
		return 2
	}
}
