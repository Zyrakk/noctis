package main

import (
	"encoding/json"
	"github.com/Zyrakk/noctis/internal/legacyimport"
	"github.com/spf13/cobra"
	"os"
)

func newLegacyInspectCmd() *cobra.Command {
	return &cobra.Command{Use: "legacy-inspect MANIFEST", Short: "Inspect local manifest allowlist; does not verify live infrastructure or G0", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		f, e := os.Open(args[0])
		if e != nil {
			return e
		}
		defer f.Close()
		resources, e := legacyimport.Inspect(f)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			Scope     string                  `json:"scope"`
			Resources []legacyimport.Resource `json:"resources"`
		}{"local_manifest_only_not_G0", resources})
	}}
}
