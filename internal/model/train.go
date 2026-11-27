package model

import (
	"errors"
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

// Feedback is the user's optional reaction to a notification. The model never
// needs it: with none, learning is fully passive.
type Feedback uint8

const (
	FeedbackNone       Feedback = iota
	FeedbackOK                  // dismissed: trained on as normal with weight 3
	FeedbackMute                // "don't show again": same training weight as OK
	FeedbackLooksWrong          // never trained on as normal
)

// Sample is one stored flow with the bookkeeping training needs.
type Sample struct {
	Flow     Flow
	Alerted  bool // the model alerted on it when it was scored
	Feedback Feedback
}

// TrainConfig holds the nightly training knobs from the design doc.
type TrainConfig struct {
	LR           float64
	WeightDecay  float64
	Batch        int
	MaxEpochs    int
	TimeCap      time.Duration
	MaskFrac     float64
	HalfLifeDays float64
	MinRecords   int // first training waits for this many records
	RareMin      int // programs below this share the rare class
	PoisonDays   int // alerted records are kept out of training this long
	Workers      int
	Seed         uint64
}

// DefaultTrainConfig returns the v1 settings.
func DefaultTrainConfig() TrainConfig {
	return TrainConfig{LR: 1e-3, WeightDecay: 1e-4, Batch: 256, MaxEpochs: 3, TimeCap: 60 * time.Second,
		MaskFrac: 0.1, HalfLifeDays: 10, MinRecords: 10000, RareMin: 200, PoisonDays: 3, Workers: 2, Seed: 1}
}

// TrainReport says what a training run did.
type TrainReport struct {
	Used, Excluded int
	Epochs         float64 // fractional if the time cap stopped it
	Steps          int
	FinalLoss      float64
	TimedOut       bool
}

// prepared is a training row after encoding.
type prepared struct {
	in    Input
	class int
	w     float32
}

// ErrTooFewRecords means the cold-start threshold has not been reached.
var ErrTooFewRecords = errors.New("model: not enough records to train yet")

// eligible applies the poisoning guard and feedback rules, returning the
// kept samples and their feedback weights.
func eligible(samples []Sample, now time.Time, poisonDays int) (keep []int, fbWeight []float32) {
	cut := now.Add(-time.Duration(poisonDays) * 24 * time.Hour)
	for i := range samples {
		s := &samples[i]
		if s.Feedback == FeedbackLooksWrong {
			continue
		}
		if s.Alerted && s.Feedback == FeedbackNone && s.Flow.Time.After(cut) {
			continue
		}
		wt := float32(1)
		if s.Feedback == FeedbackOK || s.Feedback == FeedbackMute {
			wt = 3
		}
		keep = append(keep, i)
		fbWeight = append(fbWeight, wt)
	}
	return
}

// Train updates the model in place from samples, using now as "today".
// It fits the input standardisation on the first run, assigns program
// classes, weights rows (recency half-life, inverse-sqrt program frequency,
// feedback), and runs AdamW for up to MaxEpochs or the time cap. It does not
// rebuild the score tables: call Calibrate afterwards.
func (m *Model) Train(samples []Sample, now time.Time, cfg TrainConfig) (TrainReport, error) {
	var rep TrainReport
	keep, fb := eligible(samples, now, cfg.PoisonDays)
	rep.Used, rep.Excluded = len(keep), len(samples)-len(keep)
	if !m.Trained() && len(keep) < cfg.MinRecords {
		return rep, ErrTooFewRecords
	}
	if len(keep) == 0 {
		return rep, ErrTooFewRecords
	}
	counts := map[string]int{}
	for _, i := range keep {
		counts[samples[i].Flow.Program]++
	}
	m.St.Programs.assign(counts, cfg.RareMin)
	if !m.St.NormFit {
		fl := make([]Flow, len(keep))
		for k, i := range keep {
			fl[k] = samples[i].Flow
		}
		m.St.Norm = FitNorm(fl)
		m.St.NormFit = true
	}
	classCount := map[int]int{}
	for _, i := range keep {
		classCount[m.St.Programs.Class(samples[i].Flow.Program)]++
	}
	rows := make([]prepared, len(keep))
	var wsum float64
	for k, i := range keep {
		s := &samples[i]
		c := m.St.Programs.Class(s.Flow.Program)
		ageDays := now.Sub(s.Flow.Time).Hours() / 24
		if ageDays < 0 {
			ageDays = 0
		}
		w := math.Pow(0.5, ageDays/cfg.HalfLifeDays) / math.Sqrt(float64(classCount[c])) * float64(fb[k])
		rows[k] = prepared{in: Encode(&s.Flow, &m.St.Norm), class: c, w: float32(w)}
		wsum += w
	}
	mean := float32(wsum / float64(len(rows)))
	for k := range rows {
		rows[k].w /= mean // mean weight 1 keeps the effective learning rate steady
	}

	rng := rand.New(rand.NewPCG(cfg.Seed, uint64(now.Unix())))
	opt := newAdam(m.Net, cfg.LR, cfg.WeightDecay)
	workers := max(1, cfg.Workers)
	grads := make([]*Net, workers)
	scr := make([]Scratch, workers)
	for i := range grads {
		grads[i] = NewNetZero()
	}
	deadline := time.Now().Add(cfg.TimeCap)
	order := rng.Perm(len(rows))
	steps := 0
	var lastLoss float64
	stepsPerEpoch := (len(rows) + cfg.Batch - 1) / cfg.Batch
	total := cfg.MaxEpochs * stepsPerEpoch
	for step := 0; step < total; step++ {
		if cfg.TimeCap > 0 && time.Now().After(deadline) {
			rep.TimedOut = true
			break
		}
		if step%stepsPerEpoch == 0 && step > 0 {
			rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		}
		lo := (step % stepsPerEpoch) * cfg.Batch
		hi := min(lo+cfg.Batch, len(order))
		batch := order[lo:hi]
		var bw float32
		for _, ri := range batch {
			bw += rows[ri].w
		}
		var wg sync.WaitGroup
		losses := make([]float64, workers)
		for wk := 0; wk < workers; wk++ {
			clear(grads[wk].Data)
			wg.Add(1)
			go func(wk int) {
				defer wg.Done()
				r := rand.New(rand.NewPCG(cfg.Seed^uint64(step)*977, uint64(wk)+1))
				for bi := wk; bi < len(batch); bi += workers {
					row := &rows[batch[bi]]
					var mask [NumNum]bool
					for j := range mask {
						mask[j] = r.Float64() < cfg.MaskFrac
					}
					scr[wk].occ1 = 0
					m.Net.Forward(&row.in, &mask, &scr[wk])
					ce, mse := m.Net.LossGrad(&row.in, row.class, row.w/bw, &scr[wk], grads[wk])
					losses[wk] += float64(row.w/bw) * float64(ce+mse)
				}
			}(wk)
		}
		wg.Wait()
		for wk := 1; wk < workers; wk++ {
			for i, v := range grads[wk].Data {
				grads[0].Data[i] += v
			}
		}
		opt.step(m.Net, grads[0])
		lastLoss = 0
		for _, l := range losses {
			lastLoss += l
		}
		steps++
	}
	rep.Steps = steps
	rep.Epochs = float64(steps) / float64(stepsPerEpoch)
	rep.FinalLoss = lastLoss
	m.St.TrainedAt = now
	m.St.Records = len(rows)
	return rep, nil
}

// adam is AdamW (decoupled weight decay, applied to weight matrices and
// embeddings only, not biases or LayerNorm parameters).
type adam struct {
	lr, wd float64
	t      int
	m, v   []float32
	decay  []bool
}

func newAdam(n *Net, lr, wd float64) *adam {
	a := &adam{lr: lr, wd: wd, m: make([]float32, len(n.Data)), v: make([]float32, len(n.Data)), decay: make([]bool, len(n.Data))}
	off := 0
	for _, s := range mainSpecs {
		k := numel(s.shape)
		isW := len(s.shape) == 2
		for i := off; i < off+k; i++ {
			a.decay[i] = isW
		}
		off += k
	}
	return a
}

func (a *adam) step(n, g *Net) {
	const b1, b2, eps = 0.9, 0.999, 1e-8
	a.t++
	c1 := 1 - math.Pow(b1, float64(a.t))
	c2 := 1 - math.Pow(b2, float64(a.t))
	for i, gr := range g.Data {
		a.m[i] = b1*a.m[i] + (1-b1)*gr
		a.v[i] = b2*a.v[i] + (1-b2)*gr*gr
		mh := float64(a.m[i]) / c1
		vh := float64(a.v[i]) / c2
		upd := a.lr * mh / (math.Sqrt(vh) + eps)
		if a.decay[i] {
			upd += a.lr * a.wd * float64(n.Data[i])
		}
		n.Data[i] -= float32(upd)
	}
}
