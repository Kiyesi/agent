package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var updateCommands = flag.Bool("update", false, "rewrite testdata/commands.json")

// The docs' command reference (site/src/pages/reference/commands.astro) is
// built from testdata/commands.json. This test keeps that file the same as
// the commands themselves, so the reference cannot drift from the program.

type docFlag struct {
	Name    string `json:"name"`
	Short   string `json:"short,omitempty"`
	Usage   string `json:"usage"`
	Default string `json:"default,omitempty"`
}

type docCommand struct {
	Path    string    `json:"path"`
	Use     string    `json:"use"`
	Short   string    `json:"short"`
	Long    string    `json:"long,omitempty"`
	Example string    `json:"example,omitempty"`
	Flags   []docFlag `json:"flags,omitempty"`
}

func describe(c *cobra.Command, out *[]docCommand) {
	if c.Hidden || c.Name() == "help" {
		return
	}
	// The root too: kiyesi alone shows what needs you, and its --project and
	// --env work on every list.
	{
		d := docCommand{
			Path:    c.CommandPath(),
			Use:     c.UseLine(),
			Short:   c.Short,
			Long:    strings.TrimSpace(c.Long),
			Example: strings.TrimRight(c.Example, "\n "),
		}
		c.NonInheritedFlags().VisitAll(func(f *pflag.Flag) {
			if f.Hidden || f.Name == "help" {
				return
			}
			def := f.DefValue
			if def == "false" || def == "[]" || def == "0s" {
				def = ""
			}
			d.Flags = append(d.Flags, docFlag{Name: f.Name, Short: f.Shorthand, Usage: f.Usage, Default: def})
		})
		*out = append(*out, d)
	}
	for _, sub := range c.Commands() {
		describe(sub, out)
	}
}

func TestCommandReferenceIsCurrent(t *testing.T) {
	root := newRoot(IO{Out: io.Discard, Err: io.Discard})
	var cmds []docCommand
	describe(root, &cmds)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cmds); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "commands.json")
	if *updateCommands {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/cli -run TestCommandReferenceIsCurrent -update to create it)", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Errorf("the commands changed: run go test ./internal/cli -run TestCommandReferenceIsCurrent -update, and review the docs' command reference")
	}
}
