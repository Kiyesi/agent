package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/certs"
	"github.com/kiyesi/kiyesi/agent/internal/render"
)

// verifyNow and verifyAPI are the clock and service kiyesi verify uses. Tests replace them.
var (
	verifyNow = time.Now
	verifyAPI = func() string { return envOr("KIYESI_API", DefaultAPI) }
	verifyKey = certs.BuiltInKey
)

func newVerify(io IO) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify <file, link or id>",
		Short: "Check a Kiyesi health certificate is real, unchanged and still valid",
		Long: "Checks a health certificate's signature with Kiyesi's public key, built into\n" +
			"this program, so a downloaded certificate file is checked with no network at all.\n" +
			"Given its link or id instead, it also asks the service whether it was revoked.",
		Example: "  kiyesi verify kiyesi-certificate-web-1-3jtDKL.json\n  kiyesi verify https://kiyesi.dev/verify/?id=Qm9yX3pXnFv2kTr8aLdE1c0b",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, online, err := loadCertificate(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			key, keyFrom := verifyKey(), "built into kiyesi"
			if key == "" {
				key, keyFrom = f.PublicKey, "published by the service"
			}
			b, err := certs.Check(f, key)
			if err != nil {
				if errors.Is(err, certs.ErrBadSignature) {
					return &exitError{code: ExitFindings, msg: "✗ Not a real certificate: " + err.Error() + "."}
				}
				return &exitError{code: ExitFindings, msg: "✗ " + err.Error() + "."}
			}
			status := f.Status
			if status == "" {
				status = "valid"
				if !b.ExpiresAt.After(verifyNow()) {
					status = "expired"
				}
			}
			if asJSON {
				return render.JSON(io.Out, map[string]any{"status": status, "online": online, "certificate": b})
			}
			out := render.NewWriter(io.Out, io.Environ)
			date := func(t time.Time) string { return t.UTC().Format("2 Jan 2006") }
			switch status {
			case "valid":
				fmt.Fprintf(out, "\n%s %s\n", render.Green("✓"), render.Bold("A real Kiyesi health certificate, unchanged, valid until "+date(b.ExpiresAt)))
			case "expired":
				fmt.Fprintf(out, "\n%s %s\n", render.Amber("!"), render.Bold("A real Kiyesi health certificate, but it expired on "+date(b.ExpiresAt)))
			default:
				fmt.Fprintf(out, "\n%s %s\n", render.Red("✗"), render.Bold("A real Kiyesi health certificate, but it was revoked: it no longer holds"))
			}
			fmt.Fprintf(out, "\n  %s  %s, of %s\n", render.GradeBlock(b.Grade.Letter), render.Bold(fmt.Sprintf("%s · %d/100", b.Server, b.Grade.Score)), b.Team)
			if b.OS != "" {
				fmt.Fprintf(out, "  %s\n", b.OS)
			}
			fmt.Fprintf(out, "  %d of %d checks passed (%d run), %s, %s\n", b.Checks.Passed, b.Checks.Total, b.Checks.BasedOn,
				plural(b.Critical, "critical finding", "critical findings"), plural(b.Warnings, "warning", "warnings"))
			fmt.Fprintf(out, "  Break-in check: %s\n", b.BreakIn)
			fmt.Fprintf(out, "  Scanned %s, issued %s\n", b.ScannedAt.UTC().Format("2 Jan 2006 15:04 UTC"), date(b.IssuedAt))
			// The blank line outside the style, which would pad it with spaces.
			fmt.Fprintln(out)
			fmt.Fprintln(out, render.Grey("  Signature checked with Kiyesi's key "+keyFrom+"."))
			if !online {
				fmt.Fprintln(out, render.Grey("  Whether it was revoked is known only to the service: kiyesi verify "+b.ID))
			}
			fmt.Fprintln(out)
			if status != "valid" {
				return &exitError{code: ExitFindings}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON")
	return cmd
}

// loadCertificate reads a downloaded file, or asks the service by link or id.
func loadCertificate(ctx context.Context, arg string) (certs.File, bool, error) {
	var f certs.File
	if info, err := os.Stat(arg); err == nil && info.Mode().IsRegular() {
		data, err := os.ReadFile(arg) // #nosec G304 -- the file the person named
		if err != nil {
			return f, false, err
		}
		if json.Unmarshal(data, &f) != nil || f.Certificate == "" || f.Signature == "" {
			return f, false, usageErr("%s is not a Kiyesi certificate file", arg)
		}
		return f, false, nil
	}
	id, ok := certs.IDFrom(arg)
	if !ok {
		return f, false, usageErr("%q is not a certificate file, link or id. Example: kiyesi verify https://kiyesi.dev/verify/?id=Qm9yX3pXnFv2kTr8aLdE1c0b", arg)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(verifyAPI(), "/")+"/v1/public/certificates/"+id, nil)
	if err != nil {
		return f, false, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return f, false, &exitError{code: ExitNoAccess, msg: "The service could not be reached to check it: " + err.Error()}
	}
	defer func() { _ = res.Body.Close() }()
	switch {
	case res.StatusCode == http.StatusNotFound:
		return f, false, &exitError{code: ExitFindings, msg: "✗ No certificate has that id. It was never made, or its team was deleted."}
	case res.StatusCode != http.StatusOK:
		return f, false, &exitError{code: ExitNoAccess, msg: fmt.Sprintf("The service answered %d. Try again in a minute.", res.StatusCode)}
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&f); err != nil {
		return f, false, err
	}
	return f, true, nil
}
