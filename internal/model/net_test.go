package model

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

type goldenIO struct {
	Cat   [][]int32   `json:"cat"`
	Proto []int32     `json:"proto"`
	Num   [][]float32 `json:"num"`
	Mask  [][]bool    `json:"mask"`
	Cls   []int       `json:"cls"`
	W     []float32   `json:"w"`
	Loss  float64     `json:"loss"`
	CE    []float64   `json:"ce"`
	MSE   []float64   `json:"mse"`
	Recon [][]float32 `json:"recon"`
	PTrue []float64   `json:"p_true"`
}

func loadNet(t *testing.T, path string) *Net {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := DecodeWeights(b)
	if err != nil {
		t.Fatal(err)
	}
	n := NewNetZero()
	if err := n.LoadWeightFile(w); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestParamCount(t *testing.T) {
	if got := ParamCount(); got != 94180 {
		t.Fatalf("param count %d, want 94180", got)
	}
}

// TestAgainstPyTorch checks forward outputs, losses and every parameter
// gradient of the hand-written Go network against PyTorch on the same
// weights and batch (fixtures from python/trafficam_model/golden.py).
func TestAgainstPyTorch(t *testing.T) {
	net := loadNet(t, "testdata/golden_main.tcw")
	want := loadNet(t, "testdata/golden_main_grads.tcw")
	var io goldenIO
	raw, err := os.ReadFile("testdata/golden_io.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &io); err != nil {
		t.Fatal(err)
	}
	grad := NewNetZero()
	var sumW float32
	for _, w := range io.W {
		sumW += w
	}
	var s Scratch
	var loss float64
	for i := range io.Cls {
		var in Input
		copy(in.Cat[:], io.Cat[i])
		in.Proto = io.Proto[i]
		copy(in.Num[:], io.Num[i])
		var mask [NumNum]bool
		copy(mask[:], io.Mask[i])
		net.Forward(&in, &mask, &s)
		if d := math.Abs(float64(s.Probs()[io.Cls[i]]) - io.PTrue[i]); d > 1e-5 {
			t.Errorf("sample %d: p(true) off by %g", i, d)
		}
		for j := range s.Recon {
			if d := math.Abs(float64(s.Recon[j] - io.Recon[i][j])); d > 1e-4 {
				t.Errorf("sample %d recon[%d] off by %g", i, j, d)
			}
		}
		ce, mse := net.LossGrad(&in, io.Cls[i], io.W[i]/sumW, &s, grad)
		if d := math.Abs(float64(ce) - io.CE[i]); d > 1e-4 {
			t.Errorf("sample %d ce off by %g", i, d)
		}
		if d := math.Abs(float64(mse) - io.MSE[i]); d > 1e-4 {
			t.Errorf("sample %d mse off by %g", i, d)
		}
		loss += float64(io.W[i]/sumW) * float64(ce+mse)
	}
	if math.Abs(loss-io.Loss) > 1e-4 {
		t.Errorf("loss %g, pytorch %g", loss, io.Loss)
	}
	for _, sp := range mainSpecs {
		g, w := grad.Tensor(sp.name), want.Tensor(sp.name)
		var maxAbs, maxErr float64
		for i := range g {
			maxAbs = math.Max(maxAbs, math.Abs(float64(w[i])))
			maxErr = math.Max(maxErr, math.Abs(float64(g[i]-w[i])))
		}
		if maxErr > 1e-5+2e-3*maxAbs {
			t.Errorf("grad %s: max error %g (max |grad| %g)", sp.name, maxErr, maxAbs)
		}
	}
}

// TestFiniteDifference is an independent check that does not need PyTorch.
func TestFiniteDifference(t *testing.T) {
	net := NewNet(7)
	in := Input{Cat: [NumCat]int32{5, 9, 3, 2, 1}, Proto: 2}
	for j := range in.Num {
		in.Num[j] = float32(math.Sin(float64(j)))
	}
	var s Scratch
	lossAt := func() float64 {
		net.Forward(&in, nil, &s)
		var mse float64
		for j := 0; j < NumNum; j++ {
			d := float64(s.Recon[j] - in.Num[j])
			mse += d * d / NumNum
		}
		return -s.LogProb(11) + mse
	}
	grad := NewNetZero()
	net.Forward(&in, nil, &s)
	net.LossGrad(&in, 11, 1, &s, grad)
	for _, name := range []string{"w1", "ln1_g", "w2", "ln2_b", "wa", "wb1", "wb2", "bb2", "emb_dest"} {
		p, g := net.Tensor(name), grad.Tensor(name)
		// probe the largest-gradient entry
		k := 0
		for i := range g {
			if math.Abs(float64(g[i])) > math.Abs(float64(g[k])) {
				k = i
			}
		}
		const h = 1e-2
		orig := p[k]
		p[k] = orig + h
		up := lossAt()
		p[k] = orig - h
		dn := lossAt()
		p[k] = orig
		fd := (up - dn) / (2 * h)
		if math.Abs(fd-float64(g[k])) > 2e-2*math.Max(1, math.Abs(fd)) {
			t.Errorf("%s[%d]: analytic %g, numeric %g", name, k, g[k], fd)
		}
	}
}

func TestWeightsRoundTripAndTamper(t *testing.T) {
	n := NewNet(3)
	meta := map[string]json.RawMessage{"x": json.RawMessage(`1`)}
	b, err := n.ToWeightFile(meta).Encode()
	if err != nil {
		t.Fatal(err)
	}
	w, err := DecodeWeights(b)
	if err != nil {
		t.Fatal(err)
	}
	m := NewNetZero()
	if err := m.LoadWeightFile(w); err != nil {
		t.Fatal(err)
	}
	for i := range n.Data {
		if n.Data[i] != m.Data[i] {
			t.Fatalf("param %d differs after round trip", i)
		}
	}
	b[len(b)/2] ^= 1
	if _, err := DecodeWeights(b); err == nil {
		t.Fatal("tampered file accepted")
	}
	if _, err := DecodeWeights(b[:100]); err == nil {
		t.Fatal("truncated file accepted")
	}
}
