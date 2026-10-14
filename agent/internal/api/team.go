package api

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Teammate is one person on the Team and security screen.
type Teammate struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Email *string `json:"email"`
	You   bool    `json:"you"`
	Role  struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"role"`
	CanSee     string     `json:"canSee"`
	EndsAt     *time.Time `json:"endsAt"`
	Area       *string    `json:"area"`
	AlertsGoTo string     `json:"alertsGoTo"`
	TwoStep    bool       `json:"twoStep"`
}

// Invite is an invite not yet accepted.
type Invite struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  struct {
		Name string `json:"name"`
	} `json:"role"`
	Expired   bool      `json:"expired"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Roster is everyone in the team, and the invites waiting.
type Roster struct {
	People  []Teammate `json:"people"`
	Invites []Invite   `json:"invites"`
}

// Team lists the people in the team.
func (c *Client) Team(ctx context.Context) (Roster, error) {
	var out Roster
	err := c.do(ctx, http.MethodGet, "/v1/team", nil, &out)
	return out, err
}

// InviteResult says whether the invite was emailed; if not, the link to pass on.
type InviteResult struct {
	Emailed bool   `json:"emailed"`
	Link    string `json:"link"`
}

// InvitePerson invites someone by email into a role, with what they work on.
func (c *Client) InvitePerson(ctx context.Context, email, role, area string) (InviteResult, error) {
	var out InviteResult
	body := map[string]any{"email": email, "role": role, "area": nil}
	if area != "" {
		body["area"] = area
	}
	err := c.do(ctx, http.MethodPost, "/v1/team/invites", body, &out)
	return out, err
}

// WorkRow is one thing that needs doing, as Assigned work shows it.
type WorkRow struct {
	Key      string     `json:"key"`
	Kind     string     `json:"kind"`
	Title    string     `json:"title"`
	Where    string     `json:"where"`
	Severity string     `json:"severity"`
	Since    *time.Time `json:"since"`
	State    string     `json:"state"`
	Owner    *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"owner"`
	Note    *string `json:"note"`
	LastFix *struct {
		Note string  `json:"note"`
		By   *string `json:"by"`
	} `json:"lastFix"`
}

// WorkList is Assigned work: unassigned first, then each person.
type WorkList struct {
	Counts struct {
		Everyone   int `json:"everyone"`
		Mine       int `json:"mine"`
		Unassigned int `json:"unassigned"`
	} `json:"counts"`
	Unassigned []WorkRow `json:"unassigned"`
	People     []struct {
		ID    string    `json:"id"`
		Name  string    `json:"name"`
		You   bool      `json:"you"`
		Open  int       `json:"open"`
		Items []WorkRow `json:"items"`
	} `json:"people"`
	Incomplete bool `json:"incomplete"`
}

// Work lists Assigned work: filter is everyone, mine or unassigned.
func (c *Client) Work(ctx context.Context, filter string) (WorkList, error) {
	var out WorkList
	err := c.do(ctx, http.MethodGet, "/v1/work?filter="+url.QueryEscape(filter), nil, &out)
	return out, err
}

// WorkSuggestion is who Kiyesi suggests for an item, and who it may go to.
type WorkSuggestion struct {
	Suggestion *struct {
		UserID string `json:"userId"`
		Reason string `json:"reason"`
	} `json:"suggestion"`
	Candidates []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Open int    `json:"open"`
		You  bool   `json:"you"`
	} `json:"candidates"`
	NotListed []string `json:"notListed"`
}

// SuggestOwner says who Kiyesi suggests for an item, and why.
func (c *Client) SuggestOwner(ctx context.Context, key string) (WorkSuggestion, error) {
	var out WorkSuggestion
	err := c.do(ctx, http.MethodGet, "/v1/work/suggest?key="+url.QueryEscape(key), nil, &out)
	return out, err
}

// Assign gives an item to someone, who is told with the note.
func (c *Client) Assign(ctx context.Context, key, to, note string) error {
	body := map[string]any{"key": key, "to": to, "note": nil}
	if note != "" {
		body["note"] = note
	}
	return c.do(ctx, http.MethodPost, "/v1/work/assign", body, nil)
}

// AckWork acknowledges any item of work.
func (c *Client) AckWork(ctx context.Context, key string) error {
	return c.do(ctx, http.MethodPost, "/v1/work/ack", map[string]string{"key": key}, nil)
}

// FixWork marks any item of work fixed, with what fixed it.
func (c *Client) FixWork(ctx context.Context, key, note string) error {
	return c.do(ctx, http.MethodPost, "/v1/work/fix", map[string]string{"key": key, "note": note}, nil)
}

// ActivityLine is one line of the activity log.
type ActivityLine struct {
	At time.Time `json:"at"`
	By *struct {
		Name string `json:"name"`
	} `json:"by"`
	ByLabel  *string `json:"byLabel"`
	Sentence string  `json:"sentence"`
}

// Activity is the activity log, newest first, a page at a time.
func (c *Client) Activity(ctx context.Context, limit int) ([]ActivityLine, error) {
	var out struct {
		Lines []ActivityLine `json:"lines"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/activity?limit="+strconv.Itoa(limit), nil, &out)
	return out.Lines, err
}

// MyAccess is your own role, where it applies and until when.
type MyAccess struct {
	Role struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"role"`
	Levels   map[string]string `json:"levels"`
	Switches map[string]bool   `json:"switches"`
	CanSee   string            `json:"canSee"`
	EndsAt   *time.Time        `json:"endsAt"`
	Team     *string           `json:"team"`
}

// WhoAmI is your own access.
func (c *Client) WhoAmI(ctx context.Context) (MyAccess, error) {
	var out MyAccess
	err := c.do(ctx, http.MethodGet, "/v1/me/access", nil, &out)
	return out, err
}

// Role is a built-in role or one the team made.
type Role struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	BuiltIn    bool              `json:"builtIn"`
	Levels     map[string]string `json:"levels"`
	CopiedFrom *string           `json:"copiedFrom"`
	People     []struct {
		Name string `json:"name"`
	} `json:"people"`
}

// Roles lists every role of the team.
func (c *Client) Roles(ctx context.Context) ([]Role, error) {
	var out struct {
		Roles []Role `json:"roles"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/roles", nil, &out)
	return out.Roles, err
}

// Project is one of the team's projects.
type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Projects lists the projects you can see.
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	var out struct {
		Projects []Project `json:"projects"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/projects", nil, &out)
	return out.Projects, err
}

// AccessScope is where someone's access applies.
type AccessScope struct {
	All      bool            `json:"all"`
	Projects []ProjectAccess `json:"projects,omitempty"`
	LeftOut  []string        `json:"leftOut,omitempty"`
}

// ProjectAccess is one project, in all environments (nil) or some.
type ProjectAccess struct {
	ProjectID    string   `json:"projectId"`
	Environments []string `json:"environments"`
}

// SetAccess sets one person's role, where it applies, and until when (a
// day such as 2026-11-30, or "" for good). It asks for the two-step code.
func (c *Client) SetAccess(ctx context.Context, userID, role string, scope AccessScope, until, code string) error {
	body := map[string]any{"role": role, "scope": scope, "endsAt": nil, "twoStepCode": code}
	if until != "" {
		body["endsAt"] = until
	}
	return c.do(ctx, http.MethodPut, "/v1/team/members/"+url.PathEscape(userID)+"/access", body, nil)
}
