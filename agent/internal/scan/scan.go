// Package scan runs the checks and turns their results into a report, with
// the grade and the wording from the pack.
package scan

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kiyesi/kiyesi/agent/internal/checks"
	"github.com/kiyesi/kiyesi/agent/internal/packs"
	"github.com/kiyesi/kiyesi/agent/internal/version"
)

// Schema names the JSON shape. It is part of the public API: change it only
// with a new version.
const Schema = "kiyesi.scan/v1"

// Report is one scan, ready to print, save or send.
type Report struct {
	Schema     string        `json:"schema"`
	Version    string        `json:"version"`
	Host       Host          `json:"host"`
	StartedAt  time.Time     `json:"started_at"`
	Seconds    float64       `json:"seconds"`
	Grade      Grade         `json:"grade"`
	Counts     Counts        `json:"counts"`
	Checks     []CheckResult `json:"checks"`
	Home       Home          `json:"home_country"`
	ReportFile string        `json:"report_file,omitempty"`

	// raw is each check's result as it returned it, for kiyesi fix. It
	// is never sent or saved.
	raw map[string]checks.Result
}

// Raw returns a check's result as the check returned it, with each
// finding's key and values, on a report this program just made.
func (r Report) Raw(id string) (checks.Result, bool) {
	res, ok := r.raw[id]
	return res, ok
}

// Home is the country data should stay in, and its rule.
type Home struct {
	Code       string   `json:"code"`
	Name       string   `json:"name"`
	Rule       string   `json:"rule,omitempty"`
	LocalSites []string `json:"local_data_centres,omitempty"`
}

// Location is one row of the data-location section.
type Location struct {
	Check      string `json:"check"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Place      string `json:"place,omitempty"`
	Country    string `json:"country,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Review     bool   `json:"review,omitempty"`
	Host       string `json:"host,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Payment    bool   `json:"payment,omitempty"`
	Private    bool   `json:"private,omitempty"`
}

// Host is the server that was scanned.
type Host struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Tested bool   `json:"tested"`
	Root   bool   `json:"root"`
}

// Grade starts at 100, loses 15 for each critical finding and 5 for each
// warning. BasedOn counts the checks that ran, out of Total.
type Grade struct {
	Score   int    `json:"score"`
	Letter  string `json:"letter"`
	BasedOn int    `json:"based_on"`
	Total   int    `json:"total"`
}

// Counts sums the findings and checks.
type Counts struct {
	Critical int `json:"critical"`
	Warnings int `json:"warnings"`
	Info     int `json:"info"`
	Passed   int `json:"passed"`
	Skipped  int `json:"skipped"`
	Run      int `json:"run"`
}

// CheckResult is one check, in words.
type CheckResult struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Area       string     `json:"area"`
	Status     string     `json:"status"`
	Summary    string     `json:"summary,omitempty"`
	SkipReason string     `json:"skip_reason,omitempty"`
	Findings   []Finding  `json:"findings,omitempty"`
	Locations  []Location `json:"locations,omitempty"`
}

// Finding is one problem in words. It never holds a secret's value.
type Finding struct {
	Check      string `json:"check"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence,omitempty"`
	Sentence   string `json:"sentence"`
	Why        string `json:"why"`
	Fix        string `json:"fix"`
	// AutoFix names the kiyesi fix that makes this change, when one can:
	// sudo kiyesi fix <name>.
	AutoFix string `json:"auto_fix,omitempty"`
}

// Timeouts per check. Trivy can take minutes on a large server.
var (
	DefaultTimeout = 20 * time.Second
	SlowTimeouts   = map[string]time.Duration{
		"vulnerabilities":  5 * time.Minute,
		"secrets-in-files": time.Minute,
		// apt's dry run takes over 20 s on a 1-CPU server with little memory.
		"updates": time.Minute,
	}
)

// Run runs every check in parallel and returns the report.
func Run(ctx context.Context, env *checks.Env, reg *checks.Registry, pack *packs.Pack) Report {
	start := env.Sys.Now()
	all := reg.All()
	results := make([]checks.Result, len(all))
	var wg sync.WaitGroup
	for i, c := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = runOne(ctx, env, c)
		}()
	}
	wg.Wait()

	r := Report{
		Schema:    Schema,
		Version:   version.Version,
		StartedAt: start.UTC(),
		Host: Host{
			Name:   env.Sys.Hostname,
			OS:     env.Sys.OS.Name,
			Tested: env.Sys.OS.Tested,
			Root:   env.Sys.Root,
		},
	}
	r.raw = map[string]checks.Result{}
	for i, c := range all {
		r.Checks = append(r.Checks, describe(pack, c.ID(), results[i]))
		r.raw[c.ID()] = results[i]
	}
	r.Counts, r.Grade = grade(r.Checks, pack.TotalChecks)
	r.Home = home(env.Cfg.HomeCountry)
	r.Seconds = env.Sys.Now().Sub(start).Seconds()
	return r
}

func runOne(ctx context.Context, env *checks.Env, c checks.Check) checks.Result {
	timeout := DefaultTimeout
	if t, ok := SlowTimeouts[c.ID()]; ok {
		timeout = t
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan checks.Result, 1)
	go func() {
		// A bug in one check must not stop the scan: it is skipped, never passed.
		defer func() {
			if p := recover(); p != nil {
				done <- checks.Skip("failed", map[string]string{"reason": fmt.Sprint("internal error: ", p)})
			}
		}()
		done <- c.Run(ctx, env)
	}()
	select {
	case res := <-done:
		return res
	case <-ctx.Done():
		return checks.Skip("timeout", nil)
	}
}

// describe turns a result into words from the pack.
func describe(pack *packs.Pack, id string, res checks.Result) CheckResult {
	w := pack.Check(id)
	out := CheckResult{ID: id, Name: w.Name, Area: w.Area, Status: string(res.Status)}
	for _, l := range res.Locations {
		out.Locations = append(out.Locations, Location{
			Check: id, Kind: l.Kind, Name: l.Name, Place: l.Place, Country: l.Country,
			Confidence: l.Confidence, Review: l.Review, Host: l.Host, Provider: l.Provider, Payment: l.Payment, Private: l.Private,
		})
	}
	switch res.Status {
	case checks.StatusPass:
		line := w.Passed
		if res.None && w.PassedNone != "" {
			line = w.PassedNone
		}
		out.Summary = packs.Fill(line, res.Vars)
	case checks.StatusSkip:
		line := w.Skips[res.SkipKey]
		if line == "" {
			line = pack.Skips[res.SkipKey]
		}
		if line == "" {
			line = res.SkipKey
		}
		out.SkipReason = packs.Fill(line, res.SkipVars)
	case checks.StatusFail:
		for _, f := range res.Findings {
			ft, ok := w.Findings[f.Key]
			if !ok {
				out.Findings = append(out.Findings, Finding{Check: id, Severity: "warning", Sentence: id + ": " + f.Key, Why: "No wording for this finding.", Fix: "Report this to Kiyesi."})
				continue
			}
			fix, auto := ft.Fix, ft.Auto
			if v, ok := ft.FixVariants[f.Variant]; ok && f.Variant != "" {
				fix = v
			}
			if f.Variant != "" {
				auto = "" // a variant, such as a certificate Caddy looks after, needs a person
			}
			confidence := ft.Confidence
			if f.Confidence != "" {
				confidence = f.Confidence
			}
			out.Findings = append(out.Findings, Finding{
				Check:      id,
				Severity:   ft.Severity,
				Confidence: confidence,
				Sentence:   strings.TrimSpace(packs.Fill(ft.Sentence, f.Vars)),
				Why:        strings.TrimSpace(packs.Fill(ft.Why, f.Vars)),
				Fix:        strings.TrimSpace(packs.Fill(fix, f.Vars)),
				AutoFix:    auto,
			})
		}
	}
	return out
}

func home(code string) Home {
	h := Home{Code: code, Name: code}
	places, err := packs.LoadPlaces()
	if err != nil {
		return h
	}
	h.Name = places.CountryName(code)
	if c := places.Country(code); c != nil {
		h.Name, h.Rule, h.LocalSites = c.Name, strings.TrimSpace(c.Rule), c.LocalDataCentres
	}
	return h
}

// grade counts the results and works out the grade. Skipped checks never
// count as passed, and a check with only info findings still passes.
func grade(cs []CheckResult, total int) (Counts, Grade) {
	var c Counts
	for _, r := range cs {
		switch r.Status {
		case string(checks.StatusPass):
			c.Passed++
			c.Run++
		case string(checks.StatusSkip):
			c.Skipped++
		case string(checks.StatusFail):
			c.Run++
			serious := false
			for _, f := range r.Findings {
				switch f.Severity {
				case "critical":
					c.Critical++
					serious = true
				case "warning":
					c.Warnings++
					serious = true
				default:
					c.Info++
				}
			}
			if !serious {
				c.Passed++
			}
		}
	}
	score := max(100-15*c.Critical-5*c.Warnings, 0)
	return c, Grade{Score: score, Letter: Letter(score), BasedOn: c.Run, Total: total}
}

// Letter is A from 90, B from 75, C from 60, D from 40, F below.
func Letter(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
