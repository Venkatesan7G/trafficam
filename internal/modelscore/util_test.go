package modelscore

import (
	"sort"

	"github.com/Venkatesan7G/trafficam/internal/event"
)

func sortSlice(m []event.Minute) {
	sort.SliceStable(m, func(i, j int) bool { return m[i].Start.Before(m[j].Start) })
}
