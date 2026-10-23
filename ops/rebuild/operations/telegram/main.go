// Bounded private inventory only; never collection, authentication or SQL.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/gotd/td/tgerr"
)

func private(path string, directory bool) error {
	i, err := os.Lstat(path)
	if err != nil || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 || i.IsDir() != directory || (!directory && !i.Mode().IsRegular()) {
		return errors.New("protected regular file0600/directory0700 required")
	}
	return nil
}
func read(path string, value any) error {
	if err := private(path, false); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
func save(root, name string, value any) error {
	f, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(value)
}
func run() error {
	credentials := flag.String("credentials", "", "Protected existing API credentials JSON")
	session := flag.String("session", "", "Protected independent session copy")
	seeds := flag.String("seeds", "", "Protected five-seed sources manifest")
	output := flag.String("output", "", "Existing empty private result directory")
	dialogs := flag.Bool("dialogs", false, "Also inventory bounded active/archive dialogs")
	flag.Parse()
	if err := private(*output, true); err != nil {
		return err
	}
	var cfg struct {
		Account string `json:"account"`
		APIID   int    `json:"api_id"`
		APIHash string `json:"api_hash"`
	}
	if err := read(*credentials, &cfg); err != nil {
		return err
	}
	var manifest struct {
		Sources []struct {
			Identity string   `json:"identity"`
			Aliases  []string `json:"aliases"`
		} `json:"sources"`
	}
	if err := read(*seeds, &manifest); err != nil {
		return err
	}
	if len(manifest.Sources) != 5 {
		return errors.New("exactly five preserved configuration seeds required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return telegramv2.RunInventory(ctx, telegramv2.ClientConfig{Account: cfg.Account, APIID: cfg.APIID, APIHash: cfg.APIHash, SessionFile: *session}, func(ctx context.Context, inventory *telegramv2.Inventory) error {
		if err := save(*output, "identity.json", map[string]any{"account": inventory.Account, "authenticated_at": time.Now().UTC(), "mode": "read-only", "updates": false, "differences": false, "session_writes": false, "database_connected": false}); err != nil {
			return err
		}
		for index, source := range manifest.Sources {
			if len(source.Aliases) == 0 {
				return errors.New("seed alias missing")
			}
			alias := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(source.Aliases[0], "https://t.me/"), "t.me/"), "@")
			result, err := inventory.Resolve(ctx, alias)
			record := map[string]any{"identity": source.Identity, "alias": alias, "account": inventory.Account, "checked_at": time.Now().UTC(), "result": result, "historical_identity": "unknown; alias may have been reassigned", "policy": "unchanged; pending explicit review"}
			if err != nil {
				record["error"] = err.Error()
			}
			if e := save(*output, fmt.Sprintf("seed-%d.json", index), record); e != nil {
				return e
			}
			if err != nil && !tgerr.Is(err, "USERNAME_INVALID", "USERNAME_NOT_OCCUPIED") {
				return err
			}
		}
		if *dialogs {
			var records []telegramv2.DialogCandidate
			if err := inventory.WalkDialogs(ctx, 32, func(candidate telegramv2.DialogCandidate) error { records = append(records, candidate); return nil }); err != nil {
				return err
			}
			return save(*output, "dialogs.json", records)
		}
		return nil
	})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "read-only inventory failed; private evidence retained; no login or collection attempted:", err)
		os.Exit(1)
	}
	fmt.Println("bounded private Telegram inventory completed; no collection or policy change")
}
