package model

import (
	"encoding/json"
	"fmt"
	"math"
)

// PriorDim is the number of transferable features head C sees.
const PriorDim = 14

// HeadC is the frozen prior-risk net: 14 -> 64 -> 64 -> 1 (ReLU, sigmoid).
// It is trained offline in Python (python/prior), shipped inside a knowledge
// pack, and never trained on the user's machine. It sees only features that
// mean the same on any machine: no IPs, domains, ports or program names.
type HeadC struct {
	Mean, Std      [PriorDim]float32
	w1, b1, w2, b2 []float32
	w3, b3         []float32
}

// PriorFeatures extracts head C's 14 raw (pre-standardisation) inputs. The
// Python side (python/prior/features.py) must stay identical; the golden
// test in headc_test.go enforces this.
func PriorFeatures(f *Flow) [PriorDim]float64 {
	return [PriorDim]float64{
		log1p(f.BytesOut),
		log1p(f.BytesIn),
		log1p(f.BytesOut / (f.BytesIn + 1)),
		log1p(f.DurationSec),
		log1p(f.SendEvents),
		math.Min(math.Max(f.IntervalCV, 0), 10),
		log1p(f.Contacts1h),
		log1p(f.FanOut60s),
		math.Min(math.Max(f.FailRate5m, 0), 1),
		b2f(f.DNSBeforeConnect),
		math.Max(f.DNSEntropy, 0),
		math.Max(f.DNSLen, 0),
		b2f(!f.SeenBefore), // destination new for this program
		b2f(f.Signed),
	}
}

// LoadHeadC builds head C from a decoded weight file of kind KindPrior.
func LoadHeadC(w *WeightFile) (*HeadC, error) {
	if w.Kind != KindPrior {
		return nil, fmt.Errorf("weights: kind %d is not a prior model", w.Kind)
	}
	h := &HeadC{}
	get := func(name string, shape ...int) ([]float32, error) {
		t, ok := w.Get(name)
		if !ok {
			return nil, fmt.Errorf("prior: missing tensor %s", name)
		}
		if numel(t.Shape) != numel(shape) || len(t.Shape) != len(shape) {
			return nil, fmt.Errorf("prior: tensor %s shape %v, want %v", name, t.Shape, shape)
		}
		return t.Data, nil
	}
	var err error
	for _, p := range []struct {
		dst   *[]float32
		name  string
		shape []int
	}{
		{&h.w1, "w1", []int{64, PriorDim}}, {&h.b1, "b1", []int{64}},
		{&h.w2, "w2", []int{64, 64}}, {&h.b2, "b2", []int{64}},
		{&h.w3, "w3", []int{1, 64}}, {&h.b3, "b3", []int{1}},
	} {
		if *p.dst, err = get(p.name, p.shape...); err != nil {
			return nil, err
		}
	}
	for _, k := range []struct {
		key string
		dst *[PriorDim]float32
	}{{"norm_mean", &h.Mean}, {"norm_std", &h.Std}} {
		raw, ok := w.Meta[k.key]
		if !ok {
			return nil, fmt.Errorf("prior: meta %s missing", k.key)
		}
		var v []float32
		if err := json.Unmarshal(raw, &v); err != nil || len(v) != PriorDim {
			return nil, fmt.Errorf("prior: meta %s must be %d numbers", k.key, PriorDim)
		}
		copy(k.dst[:], v)
	}
	for _, s := range h.Std {
		if s <= 0 {
			return nil, fmt.Errorf("prior: non-positive std")
		}
	}
	return h, nil
}

// Risk returns the prior risk in 0..1 for a flow.
func (h *HeadC) Risk(f *Flow) float32 {
	raw := PriorFeatures(f)
	var x [PriorDim]float32
	for i, v := range raw {
		x[i] = (float32(v) - h.Mean[i]) / h.Std[i]
	}
	return h.forward(&x)
}

func (h *HeadC) forward(x *[PriorDim]float32) float32 {
	var a, b [64]float32
	for o := 0; o < 64; o++ {
		acc := h.b1[o]
		for i := 0; i < PriorDim; i++ {
			acc += h.w1[o*PriorDim+i] * x[i]
		}
		if acc < 0 {
			acc = 0
		}
		a[o] = acc
	}
	for o := 0; o < 64; o++ {
		acc := h.b2[o]
		for i := 0; i < 64; i++ {
			acc += h.w2[o*64+i] * a[i]
		}
		if acc < 0 {
			acc = 0
		}
		b[o] = acc
	}
	z := h.b3[0]
	for i := 0; i < 64; i++ {
		z += h.w3[i] * b[i]
	}
	return float32(1 / (1 + math.Exp(-float64(z))))
}
