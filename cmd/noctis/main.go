package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "noctis",
		Short:   "Private evidence intelligence; v2 runtime and historical inspection",
		Version: version,
	}

	root.AddCommand(newV2Cmd())
	root.AddCommand(newLegacyInspectCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
