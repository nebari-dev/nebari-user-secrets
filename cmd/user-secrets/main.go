// Command user-secrets is the nebari-user-secrets service binary. This slice
// provides the admin subcommand only.
package main

import (
	"fmt"
	"os"
)

const usage = "usage: user-secrets admin rotate-kek|retire-kek <id>|rotate-dek [--owner <sub>] " +
	"--actor <name> [--namespace <ns>]"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "admin":
		os.Exit(runAdmin(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}
}
