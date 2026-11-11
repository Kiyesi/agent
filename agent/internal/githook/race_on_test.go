//go:build race

package githook

// raceEnabled is true under the race detector, which makes the rules many
// times slower than a real push.
const raceEnabled = true
