// Package ramp is the gamified learning ramp shown to the user:
//
//	Listening    days 0-3    learning quietly, only the always-alert rules speak
//	Settling in  days 4-10   habits are forming, few alerts
//	Watching     days 11-30  the model is judging new behaviour
//	Guarding     day 30+     a full month of habits is known
//
// The same day boundaries are used by the model (internal/modelscore).
package ramp

import "time"

// Stage is one step of the ramp.
type Stage struct {
	Name    string `json:"name"`
	FromDay int    `json:"from_day"` // first day of this stage (day 0 = install day)
	Meaning string `json:"meaning"`
}

// Stages in order.
var Stages = []Stage{
	{"Listening", 0, "Learning how your programs normally use the network. Only the always-alert rules (known-bad and your watch list) can alert."},
	{"Settling in", 4, "Habits are forming. New programs and new destinations for quiet programs can alert."},
	{"Watching", 11, "The model now judges new behaviour against each program's own habits."},
	{"Guarding", 30, "A full month of habits is known. This is trafficam at full strength."},
}

// FullDays is when the ramp is complete.
const FullDays = 30

// Progress describes where an install is on the ramp.
type Progress struct {
	Stage    string  `json:"stage"`
	Index    int     `json:"index"`     // 0..3
	Day      int     `json:"day"`       // whole days since install (0 on the first day)
	Percent  float64 `json:"percent"`   // 0..100 toward Guarding
	NextIn   int     `json:"next_in"`   // days until the next stage (0 when Guarding)
	NextName string  `json:"next_name"` // name of the next stage ("" when Guarding)
}

// At returns the progress of an install that is age old.
func At(age time.Duration) Progress {
	if age < 0 {
		age = 0
	}
	day := int(age.Hours() / 24)
	p := Progress{Day: day, Percent: min(100, 100*age.Hours()/(24*FullDays))}
	for i, s := range Stages {
		if day >= s.FromDay {
			p.Stage, p.Index = s.Name, i
		}
	}
	if p.Index+1 < len(Stages) {
		n := Stages[p.Index+1]
		p.NextName, p.NextIn = n.Name, n.FromDay-day
	}
	return p
}
