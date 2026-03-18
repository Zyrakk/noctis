package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
	"github.com/spf13/cobra"

	"github.com/Zyrakk/noctis/internal/config"
)

func newTelegramAuthCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "telegram-auth",
		Short: "Interactively authenticate a Telegram account and save the session",
		Long:  "One-time interactive command that authenticates with Telegram using the configured credentials and saves the session file for reuse by 'noctis serve'.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			tcfg := &cfg.Sources.Telegram
			var missing []string
			if tcfg.APIId == 0 {
				missing = append(missing, "apiId")
			}
			if tcfg.APIHash == "" {
				missing = append(missing, "apiHash")
			}
			if tcfg.Phone == "" {
				missing = append(missing, "phone")
			}
			if tcfg.SessionFile == "" {
				missing = append(missing, "sessionFile")
			}
			if len(missing) > 0 {
				return fmt.Errorf("telegram config missing required fields: %s", strings.Join(missing, ", "))
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			client := telegram.NewClient(tcfg.APIId, tcfg.APIHash, telegram.Options{
				SessionStorage: &session.FileStorage{
					Path: tcfg.SessionFile,
				},
			})

			return client.Run(ctx, func(ctx context.Context) error {
				flow := auth.NewFlow(
					auth.Constant(tcfg.Phone, tcfg.Password,
						auth.CodeAuthenticatorFunc(func(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
							switch sentCode.Type.(type) {
							case *tg.AuthSentCodeTypeApp:
								fmt.Println("Code sent to your Telegram app.")
							case *tg.AuthSentCodeTypeSMS:
								fmt.Println("Code sent via SMS.")
							case *tg.AuthSentCodeTypeCall:
								fmt.Println("Code will be delivered via phone call.")
							case *tg.AuthSentCodeTypeFragmentSMS:
								fmt.Println("Code sent via Fragment SMS.")
							case *tg.AuthSentCodeTypeEmailCode:
								fmt.Println("Code sent to your login email.")
							default:
								fmt.Printf("Code sent (type: %T).\n", sentCode.Type)
							}
							fmt.Print("Enter Telegram auth code: ")
							var code string
							if _, err := fmt.Scanln(&code); err != nil {
								return "", fmt.Errorf("reading auth code: %w", err)
							}
							return strings.TrimSpace(code), nil
						}),
					),
					auth.SendCodeOptions{},
				)

				if err := client.Auth().IfNecessary(ctx, flow); err != nil {
					return fmt.Errorf("telegram auth: %w", err)
				}

				fmt.Printf("Authentication successful, session saved to %s\n", tcfg.SessionFile)
				return nil
			})
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	return cmd
}
