package checks

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// bytesText writes a size the way people say it: "512 MB", "1 GB", "3.8 GB".
func bytesText(b uint64) string {
	const gb, mb = 1 << 30, 1 << 20
	switch {
	case b >= 10*gb:
		return fmt.Sprintf("%d GB", (b+gb/2)/gb)
	case b >= gb:
		s := strconv.FormatFloat(float64(b)/gb, 'f', 1, 64)
		return strings.TrimSuffix(s, ".0") + " GB"
	default:
		return fmt.Sprintf("%d MB", (b+mb/2)/mb)
	}
}

// percentText rounds a percentage down, so 89.9% never reads as 90%.
func percentText(p float64) string { return strconv.Itoa(int(p)) }

// ageText writes a duration in hours up to two days, then in days.
func ageText(d time.Duration) string {
	h := int(d.Hours())
	switch {
	case h < 1:
		return "under an hour"
	case h == 1:
		return "1 hour"
	case h < 48:
		return fmt.Sprintf("%d hours", h)
	default:
		return fmt.Sprintf("%d days", h/24)
	}
}

// clockText writes a time of day, adding the day when it was not today.
func clockText(t, now time.Time) string {
	t = t.In(now.Location())
	y1, m1, d1 := t.Date()
	y2, m2, d2 := now.Date()
	if y1 == y2 && m1 == m2 && d1 == d2 {
		return t.Format("15:04")
	}
	if y, m, d := now.AddDate(0, 0, -1).Date(); y == y1 && m == m1 && d == d1 {
		return t.Format("15:04") + " yesterday"
	}
	return t.Format("15:04 on Mon 2 Jan")
}
