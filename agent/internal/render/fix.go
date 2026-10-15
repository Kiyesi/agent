package render

import "charm.land/lipgloss/v2"

// The styles kiyesi fix prints with. Write through NewWriter, so they are
// dropped when the output is not a terminal.

var green = lipgloss.NewStyle().Foreground(lipgloss.Green)

func Bold(s string) string  { return bold.Render(s) }
func Grey(s string) string  { return grey.Render(s) }
func Green(s string) string { return green.Render(s) }
func Amber(s string) string { return amber.Render(s) }
func Red(s string) string   { return red.Render(s) }

// GradeBlock is the grade's letter on its colour, as the report shows it.
func GradeBlock(letter string) string {
	return lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color(gradeColours[letter])).
		Render(" " + letter + " ")
}
