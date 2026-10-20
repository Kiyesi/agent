package api

import (
	"encoding/json"
	"testing"
)

// A limited scope always carries its projects, even none: the service
// refuses a limited scope without the list.
func TestLimitedScopeSendsItsProjects(t *testing.T) {
	for _, c := range []struct {
		in   AccessScope
		want string
	}{
		{AccessScope{All: false}, `{"all":false,"projects":[]}`},
		{AccessScope{All: false, LeftOut: []string{"s1"}}, `{"all":false,"projects":[],"leftOut":["s1"]}`},
		{AccessScope{All: true}, `{"all":true}`},
		{AccessScope{All: false, Projects: []ProjectAccess{{ProjectID: "p1"}}}, `{"all":false,"projects":[{"projectId":"p1","environments":null}]}`},
	} {
		b, err := json.Marshal(c.in)
		if err != nil || string(b) != c.want {
			t.Errorf("%+v: got %s, %v; want %s", c.in, b, err, c.want)
		}
	}
}
