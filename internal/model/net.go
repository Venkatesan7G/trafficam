package model

import (
	"math"
	"math/rand/v2"
)

const lnEps = 1e-5

// tensorSpec lists every parameter tensor in file order. Shapes follow
// PyTorch conventions: Linear weights are (out, in).
type tensorSpec struct {
	name  string
	shape []int
}

var mainSpecs = []tensorSpec{
	{"emb_dest", []int{4096, 16}},
	{"emb_asn", []int{1024, 8}},
	{"emb_parent", []int{512, 8}},
	{"emb_country", []int{256, 4}},
	{"emb_port", []int{16, 4}},
	{"w1", []int{Hidden1, InputDim}},
	{"b1", []int{Hidden1}},
	{"ln1_g", []int{Hidden1}},
	{"ln1_b", []int{Hidden1}},
	{"w2", []int{Bottleneck, Hidden1}},
	{"b2", []int{Bottleneck}},
	{"ln2_g", []int{Bottleneck}},
	{"ln2_b", []int{Bottleneck}},
	{"wa", []int{NumClasses, Bottleneck}},
	{"ba", []int{NumClasses}},
	{"wb1", []int{HeadBHidden, Bottleneck}},
	{"bb1", []int{HeadBHidden}},
	{"wb2", []int{NumNum, HeadBHidden}},
	{"bb2", []int{NumNum}},
}

func numel(shape []int) int {
	n := 1
	for _, d := range shape {
		n *= d
	}
	return n
}

// Net is heads A and B on the shared trunk. All parameters live in one flat
// slice so the optimiser and the serialiser treat them uniformly.
type Net struct {
	Data []float32
	t    map[string][]float32
	// views, in mainSpecs order
	emb                        [NumCat][]float32
	w1, b1, g1, e1             []float32
	w2, b2, g2, e2             []float32
	wa, ba, wb1, bb1, wb2, bb2 []float32
}

// ParamCount is the total number of parameters (94,180).
func ParamCount() int {
	n := 0
	for _, s := range mainSpecs {
		n += numel(s.shape)
	}
	return n
}

// NewNetZero returns a network with all parameters zero.
func NewNetZero() *Net {
	n := &Net{Data: make([]float32, ParamCount()), t: map[string][]float32{}}
	n.bind()
	return n
}

func (n *Net) bind() {
	off := 0
	for _, s := range mainSpecs {
		k := numel(s.shape)
		n.t[s.name] = n.Data[off : off+k : off+k]
		off += k
	}
	for i, nm := range []string{"emb_dest", "emb_asn", "emb_parent", "emb_country", "emb_port"} {
		n.emb[i] = n.t[nm]
	}
	n.w1, n.b1, n.g1, n.e1 = n.t["w1"], n.t["b1"], n.t["ln1_g"], n.t["ln1_b"]
	n.w2, n.b2, n.g2, n.e2 = n.t["w2"], n.t["b2"], n.t["ln2_g"], n.t["ln2_b"]
	n.wa, n.ba = n.t["wa"], n.t["ba"]
	n.wb1, n.bb1, n.wb2, n.bb2 = n.t["wb1"], n.t["bb1"], n.t["wb2"], n.t["bb2"]
}

// NewNet returns a freshly initialised network. Embeddings ~ N(0, 0.1);
// Linear layers use PyTorch's default U(-1/sqrt(in), 1/sqrt(in)); LayerNorm
// gains are 1.
func NewNet(seed uint64) *Net {
	n := NewNetZero()
	r := rand.New(rand.NewPCG(seed, 0x7261666669636d))
	for i := range n.emb {
		for j := range n.emb[i] {
			n.emb[i][j] = float32(r.NormFloat64() * 0.1)
		}
	}
	lin := func(w, b []float32, in int) {
		bound := 1 / math.Sqrt(float64(in))
		for i := range w {
			w[i] = float32((r.Float64()*2 - 1) * bound)
		}
		for i := range b {
			b[i] = float32((r.Float64()*2 - 1) * bound)
		}
	}
	lin(n.w1, n.b1, InputDim)
	lin(n.w2, n.b2, Hidden1)
	lin(n.wa, n.ba, Bottleneck)
	lin(n.wb1, n.bb1, Bottleneck)
	lin(n.wb2, n.bb2, HeadBHidden)
	for i := range n.g1 {
		n.g1[i] = 1
	}
	for i := range n.g2 {
		n.g2[i] = 1
	}
	return n
}

// Clone returns a deep copy.
func (n *Net) Clone() *Net {
	c := NewNetZero()
	copy(c.Data, n.Data)
	return c
}

// Tensor returns the named parameter view.
func (n *Net) Tensor(name string) []float32 { return n.t[name] }

// Scratch holds the activations of one forward pass, reused to avoid
// allocation.
type Scratch struct {
	x         [InputDim]float32
	z1, xh1   [Hidden1]float32
	h1        [Hidden1]float32
	s1        float32 // 1/sigma of LN1
	z2, xh2   [Bottleneck]float32
	h2        [Bottleneck]float32
	s2        float32
	logits    [NumClasses]float32
	probs     [NumClasses]float32
	r1pre, r1 [HeadBHidden]float32
	Recon     [NumNum]float32
	// occ1 is 1 + the index (0..25, see FeatureNames) of an input feature to
	// zero for this pass, or 0 for none. Used by explanations.
	occ1 int
}

// Probs returns head A's softmax output after Forward.
func (s *Scratch) Probs() []float32 { return s.probs[:] }

func layerNorm(z, xh, out, g, b []float32) (invStd float32) {
	n := float64(len(z))
	var mu float64
	for _, v := range z {
		mu += float64(v)
	}
	mu /= n
	var va float64
	for _, v := range z {
		d := float64(v) - mu
		va += d * d
	}
	va /= n
	inv := 1 / math.Sqrt(va+lnEps)
	for i, v := range z {
		xh[i] = float32((float64(v) - mu) * inv)
		out[i] = g[i]*xh[i] + b[i]
	}
	return float32(inv)
}

// Forward runs the network. numMask, if non-nil, zeroes numeric inputs where
// true (denoising). The numeric target for head B is always in.Num unmasked.
func (n *Net) Forward(in *Input, numMask *[NumNum]bool, s *Scratch) {
	cats := [NumCat]int32{in.Cat[0], in.Cat[1], in.Cat[2], in.Cat[3], in.Cat[4]}
	for i := 0; i < NumCat; i++ {
		d := catDims[i]
		copy(s.x[catOffsets[i]:catOffsets[i]+d], n.emb[i][int(cats[i])*d:int(cats[i])*d+d])
	}
	for i := 0; i < ProtoDim; i++ {
		s.x[EmbDim+i] = 0
	}
	s.x[EmbDim+int(in.Proto)] = 1
	for j := 0; j < NumNum; j++ {
		v := in.Num[j]
		if numMask != nil && numMask[j] {
			v = 0
		}
		s.x[EmbDim+ProtoDim+j] = v
	}
	if k := s.occ1 - 1; k >= 0 {
		lo, hi := 0, 0
		switch {
		case k < NumCat:
			lo, hi = catOffsets[k], catOffsets[k]+catDims[k]
		case k == NumCat:
			lo, hi = EmbDim, EmbDim+ProtoDim
		default:
			lo = EmbDim + ProtoDim + (k - NumCat - 1)
			hi = lo + 1
		}
		for i := lo; i < hi; i++ {
			s.x[i] = 0
		}
	}
	for o := 0; o < Hidden1; o++ {
		acc := n.b1[o]
		row := n.w1[o*InputDim : (o+1)*InputDim]
		for i, w := range row {
			acc += w * s.x[i]
		}
		s.z1[o] = acc
	}
	var y1 [Hidden1]float32
	s.s1 = layerNorm(s.z1[:], s.xh1[:], y1[:], n.g1, n.e1)
	for i, v := range y1 {
		if v < 0 {
			v = 0
		}
		s.h1[i] = v
	}
	for o := 0; o < Bottleneck; o++ {
		acc := n.b2[o]
		row := n.w2[o*Hidden1 : (o+1)*Hidden1]
		for i, w := range row {
			acc += w * s.h1[i]
		}
		s.z2[o] = acc
	}
	var y2 [Bottleneck]float32
	s.s2 = layerNorm(s.z2[:], s.xh2[:], y2[:], n.g2, n.e2)
	for i, v := range y2 {
		if v < 0 {
			v = 0
		}
		s.h2[i] = v
	}
	// head A
	maxl := float32(math.Inf(-1))
	for o := 0; o < NumClasses; o++ {
		acc := n.ba[o]
		row := n.wa[o*Bottleneck : (o+1)*Bottleneck]
		for i, w := range row {
			acc += w * s.h2[i]
		}
		s.logits[o] = acc
		if acc > maxl {
			maxl = acc
		}
	}
	var sum float64
	for o := range s.logits {
		e := math.Exp(float64(s.logits[o] - maxl))
		s.probs[o] = float32(e)
		sum += e
	}
	for o := range s.probs {
		s.probs[o] = float32(float64(s.probs[o]) / sum)
	}
	// head B
	for o := 0; o < HeadBHidden; o++ {
		acc := n.bb1[o]
		row := n.wb1[o*Bottleneck : (o+1)*Bottleneck]
		for i, w := range row {
			acc += w * s.h2[i]
		}
		s.r1pre[o] = acc
		if acc < 0 {
			acc = 0
		}
		s.r1[o] = acc
	}
	for o := 0; o < NumNum; o++ {
		acc := n.bb2[o]
		row := n.wb2[o*HeadBHidden : (o+1)*HeadBHidden]
		for i, w := range row {
			acc += w * s.r1[i]
		}
		s.Recon[o] = acc
	}
}

// LogProb returns log p(class) from head A, computed stably from logits.
func (s *Scratch) LogProb(class int) float64 {
	maxl := s.logits[0]
	for _, v := range s.logits {
		if v > maxl {
			maxl = v
		}
	}
	var sum float64
	for _, v := range s.logits {
		sum += math.Exp(float64(v - maxl))
	}
	return float64(s.logits[class]-maxl) - math.Log(sum)
}

// ReconErr returns the per-feature squared reconstruction error against in.Num.
func (s *Scratch) ReconErr(in *Input) [NumNum]float32 {
	var e [NumNum]float32
	for j := range e {
		d := s.Recon[j] - in.Num[j]
		e[j] = d * d
	}
	return e
}

// LossGrad accumulates gradients of weight*(CE_A + MSE_B) into grad and
// returns that sample's (ce, mse). The caller scales weight by 1/sum(weights)
// for a weighted mean. s must hold the matching Forward (same numMask).
func (n *Net) LossGrad(in *Input, class int, weight float32, s *Scratch, grad *Net) (ce, mse float32) {
	ce = float32(-s.LogProb(class))
	var dout [NumNum]float32
	for j := 0; j < NumNum; j++ {
		d := s.Recon[j] - in.Num[j]
		mse += d * d / NumNum
		dout[j] = weight * 2 * d / NumNum
	}
	// head B backward
	var dr1 [HeadBHidden]float32
	for o := 0; o < NumNum; o++ {
		g := dout[o]
		grad.bb2[o] += g
		wrow := n.wb2[o*HeadBHidden : (o+1)*HeadBHidden]
		grow := grad.wb2[o*HeadBHidden : (o+1)*HeadBHidden]
		for i := range wrow {
			grow[i] += g * s.r1[i]
			dr1[i] += g * wrow[i]
		}
	}
	var dh2 [Bottleneck]float32
	for o := 0; o < HeadBHidden; o++ {
		if s.r1pre[o] <= 0 {
			continue
		}
		g := dr1[o]
		grad.bb1[o] += g
		wrow := n.wb1[o*Bottleneck : (o+1)*Bottleneck]
		grow := grad.wb1[o*Bottleneck : (o+1)*Bottleneck]
		for i := range wrow {
			grow[i] += g * s.h2[i]
			dh2[i] += g * wrow[i]
		}
	}
	// head A backward
	for o := 0; o < NumClasses; o++ {
		g := s.probs[o]
		if o == class {
			g -= 1
		}
		g *= weight
		grad.ba[o] += g
		wrow := n.wa[o*Bottleneck : (o+1)*Bottleneck]
		grow := grad.wa[o*Bottleneck : (o+1)*Bottleneck]
		for i := range wrow {
			grow[i] += g * s.h2[i]
			dh2[i] += g * wrow[i]
		}
	}
	// trunk layer 2
	var dz2 [Bottleneck]float32
	lnBackward(dh2[:], s.h2[:], s.xh2[:], s.s2, n.g2, grad.g2, grad.e2, dz2[:])
	var dh1 [Hidden1]float32
	for o := 0; o < Bottleneck; o++ {
		g := dz2[o]
		grad.b2[o] += g
		wrow := n.w2[o*Hidden1 : (o+1)*Hidden1]
		grow := grad.w2[o*Hidden1 : (o+1)*Hidden1]
		for i := range wrow {
			grow[i] += g * s.h1[i]
			dh1[i] += g * wrow[i]
		}
	}
	var dz1 [Hidden1]float32
	lnBackward(dh1[:], s.h1[:], s.xh1[:], s.s1, n.g1, grad.g1, grad.e1, dz1[:])
	var dx [InputDim]float32
	for o := 0; o < Hidden1; o++ {
		g := dz1[o]
		grad.b1[o] += g
		wrow := n.w1[o*InputDim : (o+1)*InputDim]
		grow := grad.w1[o*InputDim : (o+1)*InputDim]
		for i := range wrow {
			grow[i] += g * s.x[i]
			dx[i] += g * wrow[i]
		}
	}
	cats := [NumCat]int32{in.Cat[0], in.Cat[1], in.Cat[2], in.Cat[3], in.Cat[4]}
	for i := 0; i < NumCat; i++ {
		d := catDims[i]
		dst := grad.emb[i][int(cats[i])*d : int(cats[i])*d+d]
		for k := 0; k < d; k++ {
			dst[k] += dx[catOffsets[i]+k]
		}
	}
	return ce, mse
}

// lnBackward backpropagates through ReLU (via the post-ReLU output h) and
// LayerNorm, accumulating gain/bias gradients and writing dz.
func lnBackward(dh, h, xh []float32, invStd float32, g, dg, db, dz []float32) {
	n := len(dh)
	dxh := make([]float32, n)
	var m1, m2 float64
	for i := 0; i < n; i++ {
		dy := dh[i]
		if h[i] <= 0 {
			dy = 0
		}
		dg[i] += dy * xh[i]
		db[i] += dy
		dxh[i] = dy * g[i]
		m1 += float64(dxh[i])
		m2 += float64(dxh[i] * xh[i])
	}
	m1 /= float64(n)
	m2 /= float64(n)
	for i := 0; i < n; i++ {
		dz[i] = invStd * (dxh[i] - float32(m1) - xh[i]*float32(m2))
	}
}
