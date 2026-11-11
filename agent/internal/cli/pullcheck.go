package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/kiyesi/kiyesi/agent/internal/pullcheck"
)

// maxPullcheckInput caps what kiyesi pullcheck reads from stdin.
const maxPullcheckInput = 8 << 20

// newPullcheck is the service's worker's helper: one change in as JSON on
// stdin, the findings out as JSON on stdout. It is hidden, as people run
// the checks through GitHub and, from week 43, kiyesi hook.
func newPullcheck(io IO) *cobra.Command {
	return &cobra.Command{
		Use:    "pullcheck",
		Short:  "Check one change's files for risky code (for the service's worker)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runPullcheck(ctx, io)
		},
	}
}

func runPullcheck(ctx context.Context, rw IO) error {
	fail := func(msg string) error {
		out, _ := json.Marshal(map[string]string{"error": msg})
		fmt.Fprintln(rw.Out, string(out))
		return &exitError{code: ExitUsage}
	}
	if rw.In == nil {
		return fail("no input: send the change as JSON on stdin")
	}
	raw, err := io.ReadAll(io.LimitReader(rw.In, maxPullcheckInput+1))
	if err != nil {
		return fail("reading the input: " + err.Error())
	}
	if len(raw) > maxPullcheckInput {
		return fail("the input is over 8 MB")
	}
	var in pullcheck.Input
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&in); err != nil {
		return fail("the input is not valid JSON: " + err.Error())
	}
	if err := pullcheck.Validate(in); err != nil {
		return fail(err.Error())
	}
	out := pullcheck.Check(ctx, in)
	enc := json.NewEncoder(rw.Out)
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
