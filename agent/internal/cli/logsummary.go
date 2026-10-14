package cli

import (
	"encoding/json"
	"fmt"
	"strings"
)

// summarize gives a short, readable form of a JSON log line, such as
// Caddy's access log or pino's, or "" when the line is better as written.
// The Logs screen says it the same way (dashboard/src/lib/log-line.ts).
func summarize(text string) string {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "{") || !strings.HasSuffix(t, "}") {
		return ""
	}
	var j map[string]any
	if json.Unmarshal([]byte(t), &j) != nil {
		return ""
	}
	req := object(j["request"])
	if len(req) == 0 {
		req = object(j["req"])
	}
	method := str(req["method"])
	uri := str(req["uri"])
	if uri == "" {
		uri = str(req["url"])
	}
	uri, _, _ = strings.Cut(uri, "?")
	uri, _, _ = strings.Cut(uri, "#")
	msg := str(j["msg"])
	if msg == "" {
		msg = str(j["message"])
	}
	logger := str(j["logger"])
	join := func(parts ...string) string {
		var out []string
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		return strings.Join(out, " · ")
	}

	switch {
	case strings.HasPrefix(logger, "http.log.access") && method != "":
		status := str(j["status"])
		if status == "" {
			status = "?"
		}
		ip := str(req["client_ip"])
		if ip == "" {
			ip = str(req["remote_ip"])
		}
		took := ""
		if d, ok := j["duration"].(float64); ok {
			if d*1000 < 10 {
				took = fmt.Sprintf("%.1f ms", d*1000)
			} else {
				took = fmt.Sprintf("%.0f ms", d*1000)
			}
		}
		return join(method+" "+uri+" → "+status, took, ip)
	case strings.HasPrefix(logger, "http.log.error"):
		on := ""
		if method != "" {
			if s := str(j["status"]); s != "" {
				on = s + " "
			}
			on += method + " " + uri + ": "
		}
		return on + msg
	}
	if res := object(j["res"]); msg == "request completed" && res["statusCode"] != nil {
		took := ""
		if d, ok := j["responseTime"].(float64); ok {
			took = fmt.Sprintf("%.0f ms", d)
		}
		return join("request completed", str(res["statusCode"]), took)
	}
	if msg == "incoming request" && method != "" {
		return "incoming request · " + method + " " + uri
	}
	if msg != "" {
		if m := str(object(j["err"])["message"]); m != "" {
			return msg + ": " + m
		}
	}
	return msg
}

func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%g", x)
	}
	return ""
}
