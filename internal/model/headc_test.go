package model

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// Checks that Go's feature extraction and forward pass for head C agree with
// the Python trainer's, so a pack trained in Python means the same thing here.
func TestHeadCMatchesPython(t *testing.T) {
	b, err := os.ReadFile("testdata/golden_prior.tcw")
	if err != nil {
		t.Fatal(err)
	}
	w, err := DecodeWeights(b)
	if err != nil {
		t.Fatal(err)
	}
	h, err := LoadHeadC(w)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile("testdata/golden_prior.json")
	var cases []struct {
		Flow     Flow
		Features []float64
		Risk     float64
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for i := range cases {
		c := &cases[i]
		got := PriorFeatures(&c.Flow)
		for j := range got {
			if math.Abs(got[j]-c.Features[j]) > 1e-4*math.Max(1, math.Abs(c.Features[j])) {
				t.Errorf("case %d feature %d: go %g, python %g", i, j, got[j], c.Features[j])
			}
		}
		if d := math.Abs(float64(h.Risk(&c.Flow)) - c.Risk); d > 1e-4 {
			t.Errorf("case %d risk off by %g", i, d)
		}
	}
}

func TestHeadCRejectsWrongKind(t *testing.T) {
	if _, err := LoadHeadC(&WeightFile{Kind: KindMain}); err == nil {
		t.Fatal("accepted a main-model file as a prior")
	}
}
