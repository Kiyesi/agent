package api

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Report is a monthly report for a project, or the data map report.
type Report struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Period      string    `json:"period"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	MadeAt      time.Time `json:"madeAt"`
	ByKiyesi    bool      `json:"byKiyesi"`
	CanShare    bool      `json:"canShare"`
	CanDownload bool      `json:"canDownload"`
	Project     *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"project"`
}

// ReportList is every report you can see, and the projects you can report on.
type ReportList struct {
	Reports  []Report `json:"reports"`
	Projects []struct {
		ID             string  `json:"id"`
		Name           string  `json:"name"`
		FirstFullMonth *string `json:"firstFullMonth"`
	} `json:"projects"`
	CanMake  bool `json:"canMake"`
	Printing bool `json:"printing"`
}

// Share is a read-only link to a report, shown once.
type Share struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ReportCard is the Monday report card.
type ReportCard struct {
	Content struct {
		Label      string `json:"label"`
		Caught     int    `json:"caught"`
		Fixed      int    `json:"fixed"`
		FixMinutes *int   `json:"fixMinutes"`
		Summary    string `json:"summary"`
		Incidents  struct {
			Total int `json:"total"`
			Fixed int `json:"fixed"`
		} `json:"incidents"`
	} `json:"content"`
}

// Reports lists the reports you can see.
func (c *Client) Reports(ctx context.Context) (ReportList, error) {
	var out ReportList
	err := c.do(ctx, http.MethodGet, "/v1/reports", nil, &out)
	return out, err
}

// MakeMonthly makes a whole past month's report for a project.
func (c *Client) MakeMonthly(ctx context.Context, projectID, month string) (Report, error) {
	var out Report
	err := c.do(ctx, http.MethodPost, "/v1/reports", map[string]string{"kind": "monthly", "projectId": projectID, "month": month}, &out)
	return out, err
}

// MakeDataMapReport makes the data map report for an auditor.
func (c *Client) MakeDataMapReport(ctx context.Context) (Report, error) {
	var out Report
	err := c.do(ctx, http.MethodPost, "/v1/reports", map[string]string{"kind": "datamap"}, &out)
	return out, err
}

// ShareReport makes a read-only link that lasts 7, 30 or 90 days.
func (c *Client) ShareReport(ctx context.Context, id string, days int) (Share, error) {
	var out Share
	err := c.do(ctx, http.MethodPost, "/v1/reports/"+url.PathEscape(id)+"/shares", map[string]int{"days": days}, &out)
	return out, err
}

// ReportPDF prints a report to PDF.
func (c *Client) ReportPDF(ctx context.Context, id string) ([]byte, error) {
	return c.send(ctx, http.MethodGet, "/v1/reports/"+url.PathEscape(id)+"/pdf", nil)
}

// ReportHTML is a report as the page its readers see.
func (c *Client) ReportHTML(ctx context.Context, id string) (string, error) {
	var out struct {
		HTML string `json:"html"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/reports/"+url.PathEscape(id), nil, &out)
	return out.HTML, err
}

// Card is last week's report card, or this week's so far.
func (c *Client) Card(ctx context.Context, thisWeek bool) (ReportCard, error) {
	week := "last"
	if thisWeek {
		week = "this"
	}
	var out ReportCard
	err := c.do(ctx, http.MethodGet, "/v1/reports/card?week="+week, nil, &out)
	return out, err
}
