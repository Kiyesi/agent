package system

import (
	"context"
	"testing"
	"time"
)

type listDocker struct{ list []Container }

func (d listDocker) Containers(context.Context) ([]Container, error) { return d.list, nil }
func (d listDocker) Dies(context.Context, time.Time, time.Time) (map[string]int, error) {
	return map[string]int{"a": 1, "d": 3}, nil
}
func (d listDocker) Logs(context.Context, string, time.Time) ([]LogLine, error) { return nil, nil }

func names(cs []Container) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func TestFilterDockerLeavesContainersOutEverywhere(t *testing.T) {
	d := listDocker{list: []Container{
		{ID: "a", Name: "/kiyesi-api-1"},
		{ID: "d", Name: "/kiyesi-drill-app-1"},
		{ID: "w", Name: "/kiyesi-drill-web-1"},
	}}
	ctx := context.Background()

	if _, same := FilterDocker(d, nil, nil).(listDocker); !same {
		t.Errorf("no patterns should keep the same reader")
	}
	ex := FilterDocker(d, nil, []string{"kiyesi-drill-*"})
	cs, _ := ex.Containers(ctx)
	if got := names(cs); len(got) != 1 || got[0] != "/kiyesi-api-1" {
		t.Errorf("exclude: %v", got)
	}
	dies, _ := ex.Dies(ctx, time.Time{}, time.Time{})
	if len(dies) != 1 || dies["a"] != 1 {
		t.Errorf("a left-out container's stops must not count: %v", dies)
	}
	in := FilterDocker(d, []string{"kiyesi-drill-*"}, []string{"*-web-1"})
	cs, _ = in.Containers(ctx)
	if got := names(cs); len(got) != 1 || got[0] != "/kiyesi-drill-app-1" {
		t.Errorf("include and exclude: %v", got)
	}
}
