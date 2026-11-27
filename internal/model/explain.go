package model

import (
	"fmt"
	"math"
	"sort"
)

// Reason is one input feature's share of why a flow looked unusual.
type Reason struct {
	Feature string  // one of FeatureNames
	Share   float64 // 0..1; shares of all reasons sum to 1
	Text    string  // short human-readable sentence
}

// Explain ranks the input features by how much they contributed to the flow's
// score and returns the top n.
//
// Two sources are blended, weighted by which head found the flow more
// unusual (PctA vs PctB):
//   - Head A: occlusion. Each of the 26 features is blanked in turn (zero
//     embedding, or the training mean for a numeric) and we measure how much
//     the program-identity surprise falls. A big fall means that feature is
//     what made the flow look like it was not from this program.
//   - Head B: each numeric feature's reconstruction error relative to its
//     usual error across the machine's history.
//
// It runs 27 forward passes, so call it for alerts only, not for every flow.
func (m *Model) Explain(f *Flow, r Result, n int) []Reason {
	var s Scratch
	in := r.In
	base := r.SurpriseA
	const nFeat = 6 + NumNum
	var cA, cB [nFeat]float64
	for k := 0; k < nFeat; k++ {
		s.occ1 = k + 1
		m.Net.Forward(&in, nil, &s)
		if d := base - (-s.LogProb(r.Class)); d > 0 {
			cA[k] = d
		}
	}
	s.occ1 = 0
	m.Net.Forward(&in, nil, &s)
	e := s.ReconErr(&in)
	for j := 0; j < NumNum; j++ {
		rel := float64(e[j]) / (float64(m.St.MeanErr[j]) + 1e-3)
		if rel > 1 {
			cB[6+j] = rel - 1
		}
	}
	norm := func(c *[nFeat]float64) {
		var t float64
		for _, v := range c {
			t += v
		}
		if t > 0 {
			for i := range c {
				c[i] /= t
			}
		}
	}
	norm(&cA)
	norm(&cB)
	wA, wB := r.PctA, r.PctB
	if wA+wB == 0 {
		wA, wB = 1, 1
	}
	wA, wB = wA/(wA+wB), wB/(wA+wB)
	share := make([]float64, nFeat)
	for k := range share {
		share[k] = wA*cA[k] + wB*cB[k]
	}
	// A destination this program has never used is the clearest reason there
	// is; make sure it is on the list even when the network is unsure.
	if !f.SeenBefore {
		share[0] += 0.5
	}
	var tot float64
	for _, v := range share {
		tot += v
	}
	idx := make([]int, 0, nFeat)
	for k, v := range share {
		if v > 0 {
			idx = append(idx, k)
		}
	}
	sort.Slice(idx, func(a, b int) bool { return share[idx[a]] > share[idx[b]] })
	if len(idx) > n {
		idx = idx[:n]
	}
	out := make([]Reason, 0, len(idx))
	for _, k := range idx {
		out = append(out, Reason{Feature: FeatureNames[k], Share: share[k] / tot, Text: m.reasonText(k, f, &in, &s)})
	}
	return out
}

func (m *Model) reasonText(k int, f *Flow, in *Input, s *Scratch) string {
	prog := f.Program
	switch k {
	case 0:
		if !f.SeenBefore {
			return fmt.Sprintf("%s has never contacted %s before", prog, f.Dest)
		}
		return fmt.Sprintf("%s rarely contacts %s", prog, f.Dest)
	case 1:
		return fmt.Sprintf("network owner (ASN %d) is unusual for %s", f.ASN, prog)
	case 2:
		return fmt.Sprintf("%s was started by an unusual parent (%s)", prog, f.Parent)
	case 3:
		return fmt.Sprintf("country %s is unusual for %s", f.Country, prog)
	case 4:
		return fmt.Sprintf("port %d is unusual for %s", f.Port, prog)
	case 5:
		return fmt.Sprintf("direction or protocol is unusual for %s", prog)
	}
	j := k - 6
	dir := "different from"
	if d := s.Recon[j] - in.Num[j]; math.Abs(float64(d)) > 0.1 {
		if d < 0 {
			dir = "higher than"
		} else {
			dir = "lower than"
		}
	}
	return fmt.Sprintf("%s is %s expected for %s", featureLabels[j], dir, prog)
}

// featureLabels are the plain-English names of the 20 numeric features.
var featureLabels = [NumNum]string{
	"upload size", "download size", "upload/download balance", "connection length", "number of sends",
	"time of day", "time of day", "day of week", "day of week",
	"timing regularity", "contact frequency", "number of hosts contacted", "failure rate",
	"DNS lookup before connecting", "domain-name randomness", "domain-name length",
	"familiarity of this destination", "age of this destination", "use of this destination by other programs", "code signing",
}
