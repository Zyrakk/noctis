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
		Short:   "Kubernetes-native threat intelligence daemon",
		Version: version,
	}

	root.AddCommand(newServeCmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newSourceCmd())
	root.AddCommand(newSearchCmd())
	root.AddCommand(newStatsCmd())
	root.AddCommand(newTelegramAuthCmd())
	root.AddCommand(newIOCCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
