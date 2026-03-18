package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	qrterminal "github.com/mdp/qrterminal/v3"
	"github.com/spf13/cobra"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/auth/qrlogin"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"

	"github.com/Zyrakk/noctis/internal/config"
)

func printCodeDelivery(t tg.AuthSentCodeTypeClass) {
	switch t.(type) {
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
		fmt.Printf("Code sent (type: %T).\n", t)
	}
}

func newTelegramAuthCmd() *cobra.Command {
	var configPath string
	var useSMS bool
	var useQR bool

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
			if tcfg.SessionFile == "" {
				missing = append(missing, "sessionFile")
			}
			if !useQR && tcfg.Phone == "" {
				missing = append(missing, "phone")
			}
			if len(missing) > 0 {
				return fmt.Errorf("telegram config missing required fields: %s", strings.Join(missing, ", "))
			}

			// Remove stale session file to ensure a clean auth attempt.
			if err := os.Remove(tcfg.SessionFile); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing stale session file: %w", err)
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if useQR {
				return runQRAuth(ctx, tcfg)
			}
			return runCodeAuth(ctx, tcfg, useSMS)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	cmd.Flags().BoolVar(&useSMS, "sms", false, "resend auth code via SMS instead of in-app delivery")
	cmd.Flags().BoolVar(&useQR, "qr", false, "use QR code login (scan with Telegram app)")
	cmd.MarkFlagsMutuallyExclusive("sms", "qr")
	return cmd
}

func newAuthClient(tcfg *config.TelegramConfig, handler telegram.UpdateHandler) *telegram.Client {
	return telegram.NewClient(tcfg.APIId, tcfg.APIHash, telegram.Options{
		UpdateHandler: handler,
		SessionStorage: &session.FileStorage{
			Path: tcfg.SessionFile,
		},
		Device: telegram.DeviceConfig{
			DeviceModel:    "Noctis",
			SystemVersion:  "Linux",
			AppVersion:     version,
			SystemLangCode: "en",
			LangCode:       "en",
		},
	})
}

func runQRAuth(ctx context.Context, tcfg *config.TelegramConfig) error {
	dispatcher := tg.NewUpdateDispatcher()
	loggedIn := qrlogin.OnLoginToken(dispatcher)
	client := newAuthClient(tcfg, dispatcher)

	fmt.Printf("Authenticating via QR code (session: %s)...\n", tcfg.SessionFile)
	fmt.Println("Open Telegram on your phone → Settings → Devices → Link Desktop Device")

	return client.Run(ctx, func(ctx context.Context) error {
		_, err := client.QR().Auth(ctx, loggedIn, func(ctx context.Context, token qrlogin.Token) error {
			fmt.Println("\nScan this QR code with your Telegram app:")
			qrterminal.GenerateHalfBlock(token.URL(), qrterminal.L, os.Stdout)
			fmt.Printf("Or open: %s\n", token.URL())
			fmt.Printf("Token expires in %s\n", time.Until(token.Expires()).Truncate(time.Second))
			return nil
		})
		if tgerr.Is(err, "SESSION_PASSWORD_NEEDED") {
			fmt.Println("\nQR scan accepted. 2FA password required.")
			password := tcfg.Password
			if password == "" {
				fmt.Print("Enter 2FA password: ")
				if _, err := fmt.Scanln(&password); err != nil {
					return fmt.Errorf("reading 2FA password: %w", err)
				}
				password = strings.TrimSpace(password)
			} else {
				fmt.Println("Using 2FA password from config.")
			}
			if _, err := client.Auth().Password(ctx, password); err != nil {
				return fmt.Errorf("2FA auth: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("QR auth: %w", err)
		}

		fmt.Printf("Authentication successful, session saved to %s\n", tcfg.SessionFile)
		return nil
	})
}

func runCodeAuth(ctx context.Context, tcfg *config.TelegramConfig, useSMS bool) error {
	client := newAuthClient(tcfg, nil)

	fmt.Printf("Authenticating %s (session: %s)...\n", tcfg.Phone, tcfg.SessionFile)

	return client.Run(ctx, func(ctx context.Context) error {
		api := client.API()

		flow := auth.NewFlow(
			auth.Constant(tcfg.Phone, tcfg.Password,
				auth.CodeAuthenticatorFunc(func(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
					printCodeDelivery(sentCode.Type)

					if useSMS {
						fmt.Println("Requesting SMS resend...")
						resent, err := api.AuthResendCode(ctx, &tg.AuthResendCodeRequest{
							PhoneNumber:   tcfg.Phone,
							PhoneCodeHash: sentCode.PhoneCodeHash,
						})
						if err != nil {
							return "", fmt.Errorf("resending code via SMS: %w", err)
						}
						if sc, ok := resent.(*tg.AuthSentCode); ok {
							printCodeDelivery(sc.Type)
						} else {
							fmt.Printf("Resend response: %T\n", resent)
						}
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
}
