package render

import (
	"fmt"

	"charm.land/lipgloss/v2"
)

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

// GradeLetter is the grade's letter in its colour, with no block around it.
func GradeLetter(letter string) string {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(gradeColours[letter])).Render(letter)
}

// GradeMove is a grade's change after a fix, an undo or a guarded command:
// "GRADE  F 25 → F 35/100  +10", with a cheer only on reaching A.
func GradeMove(beforeLetter string, before int, afterLetter string, after int) string {
	line := fmt.Sprintf("%s  %s %d → %s %s", Bold("GRADE"), GradeLetter(beforeLetter), before,
		GradeLetter(afterLetter), Bold(fmt.Sprintf("%d/100", after)))
	switch d := after - before; {
	case d > 0 && afterLetter == "A":
		line += "  " + Green(fmt.Sprintf("+%d", d)) + " 🎉"
	case d > 0:
		line += "  " + Green(fmt.Sprintf("+%d", d))
	case d < 0:
		line += "  " + Red(fmt.Sprintf("−%d", -d))
	}
	return line
}
