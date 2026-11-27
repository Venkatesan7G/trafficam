package model

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"time"
)

// Quantile levels at which per-program score distributions are stored. The
// fine tail lets the alert line sit at the top 0.01 % of a program's history.
var quantileLevels = func() []float64 {
	l := make([]float64, 0, 104)
	for i := 0; i <= 99; i++ {
		l = append(l, float64(i))
	}
	return append(l, 99.5, 99.9, 99.99, 100)
}()

// Quantiles is one program's stored score distribution: the score values at
// quantileLevels, for head A's surprise and head B's reconstruction error.
type Quantiles struct {
	A []float32 `json:"a"`
	B []float32 `json:"b"`
	N int       `json:"n"`
}

// State is everything the model learns besides the network weights.
type State struct {
	Version   int                `json:"version"`
	Norm      Norm               `json:"norm"`
	NormFit   bool               `json:"norm_fit"`
	Programs  *Programs          `json:"programs"`
	Quant     map[int]*Quantiles `json:"quant"` // class -> table; -1 = pooled over all programs
	MeanErr   [NumNum]float32    `json:"mean_err"`
	AlertLine float64            `json:"alert_line"`
	TrainedAt time.Time          `json:"trained_at"`
	Records   int                `json:"records"`
}

// Config holds the scoring knobs. All values are guesses until measured on
// real traffic; they are collected here so they can be tuned in one place.
type Config struct {
	NewDestBump  float64 // points added when the program has never used this destination
	PriorMax     float64 // head C's cap in percentile points (design doc: 15)
	UnusualFloor float64 // head C only applies once the local score reaches this
	DefaultLine  float64 // alert line before the model has calibrated one
	AlertsPerDay float64 // target alert rate used to self-set the line
	MinProgramN  int     // samples needed for a program's own percentile table
}

// DefaultConfig returns the v1 settings.
func DefaultConfig() Config {
	return Config{NewDestBump: 10, PriorMax: 15, UnusualFloor: 80, DefaultLine: 99.5, AlertsPerDay: 1.5, MinProgramN: 50}
}

// Model is the learned part of trafficam: the network, its state and the
// optional frozen prior. A Model is not safe for concurrent use; the service
// scores on one goroutine and swaps in a new Model after nightly training.
type Model struct {
	Net   *Net
	St    State
	Prior *HeadC // may be nil: head C is a user switch
	Cfg   Config
}

// New returns an untrained model.
func New(seed uint64) *Model {
	return &Model{
		Net: NewNet(seed),
		St:  State{Version: 1, Norm: IdentityNorm(), Programs: newPrograms(), Quant: map[int]*Quantiles{}, AlertLine: 0},
		Cfg: DefaultConfig(),
	}
}

// Clone deep-copies the model (the prior is shared: it is frozen).
func (m *Model) Clone() *Model {
	c := &Model{Net: m.Net.Clone(), St: m.St, Prior: m.Prior, Cfg: m.Cfg}
	c.St.Programs = m.St.Programs.clone()
	c.St.Quant = make(map[int]*Quantiles, len(m.St.Quant))
	for k, v := range m.St.Quant {
		c.St.Quant[k] = v
	}
	return c
}

// Trained reports whether the model has been trained at least once.
func (m *Model) Trained() bool { return !m.St.TrainedAt.IsZero() }

// Result is the model's judgement of one flow.
type Result struct {
	Score     float64 // 0..~125; higher = more unusual for this program
	PctA      float64 // percentile of head A's surprise within the program's history
	PctB      float64 // percentile of head B's reconstruction error
	SurpriseA float64 // -log p(program | flow)
	SurpriseB float64 // mean squared reconstruction error
	Prior     float64 // head C's risk, 0 if head C is off
	PriorBump float64 // points head C added
	Alert     bool
	Class     int
	In        Input
}

// Surprise computes the two raw surprise values for a flow.
func (m *Model) Surprise(f *Flow, s *Scratch) (a, b float64, in Input, class int) {
	in = Encode(f, &m.St.Norm)
	class = m.St.Programs.Class(f.Program)
	s.occ1 = 0
	m.Net.Forward(&in, nil, s)
	a = -s.LogProb(class)
	var e float64
	for _, v := range s.ReconErr(&in) {
		e += float64(v)
	}
	return a, e / NumNum, in, class
}

// Score judges one flow. It never alerts on head C alone: the prior is added
// only once the local score is already unusual.
func (m *Model) Score(f *Flow, s *Scratch) Result {
	a, b, in, class := m.Surprise(f, s)
	r := Result{SurpriseA: a, SurpriseB: b, Class: class, In: in}
	r.PctA = m.percentile(class, a, true)
	r.PctB = m.percentile(class, b, false)
	score := math.Max(r.PctA, r.PctB)
	if !f.SeenBefore {
		score += m.Cfg.NewDestBump
	}
	if m.Prior != nil && score >= m.Cfg.UnusualFloor {
		r.Prior = float64(m.Prior.Risk(f))
		r.PriorBump = math.Min(m.Cfg.PriorMax, m.Cfg.PriorMax*r.Prior)
		score += r.PriorBump
	}
	r.Score = score
	r.Alert = m.Trained() && score > m.alertLine()
	return r
}

func (m *Model) alertLine() float64 {
	if m.St.AlertLine > 0 {
		return m.St.AlertLine
	}
	return m.Cfg.DefaultLine
}

func (m *Model) table(class int) *Quantiles {
	if q := m.St.Quant[class]; q != nil && q.N >= m.Cfg.MinProgramN {
		return q
	}
	return m.St.Quant[-1]
}

// percentile locates v within the program's stored distribution, 0..100. A
// model with no table scores everything 50 (nothing is unusual yet).
func (m *Model) percentile(class int, v float64, headA bool) float64 {
	q := m.table(class)
	if q == nil {
		return 50
	}
	t := q.B
	if headA {
		t = q.A
	}
	return interpPercentile(t, v)
}

func interpPercentile(t []float32, v float64) float64 {
	if len(t) != len(quantileLevels) {
		return 50
	}
	if v <= float64(t[0]) {
		return 0
	}
	last := len(t) - 1
	if v >= float64(t[last]) {
		return 100
	}
	i := sort.Search(len(t), func(i int) bool { return float64(t[i]) > v }) // t[i-1] <= v < t[i]
	lo, hi := float64(t[i-1]), float64(t[i])
	frac := 0.0
	if hi > lo {
		frac = (v - lo) / (hi - lo)
	}
	return quantileLevels[i-1] + frac*(quantileLevels[i]-quantileLevels[i-1])
}

func makeQuantiles(a, b []float64) *Quantiles {
	q := &Quantiles{N: len(a)}
	at := func(sorted []float64, lvl float64) float32 {
		if len(sorted) == 0 {
			return 0
		}
		pos := lvl / 100 * float64(len(sorted)-1)
		lo := int(math.Floor(pos))
		hi := int(math.Ceil(pos))
		return float32(sorted[lo] + (sorted[hi]-sorted[lo])*(pos-float64(lo)))
	}
	sort.Float64s(a)
	sort.Float64s(b)
	for _, l := range quantileLevels {
		q.A = append(q.A, at(a, l))
		q.B = append(q.B, at(b, l))
	}
	// interpolation can leave equal neighbours; keep non-decreasing for Search
	return q
}

// Save writes the model as one TCW1 file; the learned state rides in meta.
func (m *Model) Save(path string) error {
	st, err := json.Marshal(m.St)
	if err != nil {
		return err
	}
	b, err := m.Net.ToWeightFile(map[string]json.RawMessage{"state": st}).Encode()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a model saved by Save. prior may be nil.
func Load(path string, prior *HeadC) (*Model, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	w, err := DecodeWeights(b)
	if err != nil {
		return nil, err
	}
	m := New(0)
	if err := m.Net.LoadWeightFile(w); err != nil {
		return nil, err
	}
	raw, ok := w.Meta["state"]
	if !ok {
		return nil, fmt.Errorf("model file has no state")
	}
	st := State{}
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	if st.Programs == nil {
		st.Programs = newPrograms()
	}
	st.Programs.reindex()
	if st.Quant == nil {
		st.Quant = map[int]*Quantiles{}
	}
	m.St = st
	m.Prior = prior
	return m, nil
}
