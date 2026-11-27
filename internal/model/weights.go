package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
)

// TCW1 is the one weight-file format shared by Go and Python.
//
//	"TCW1"            4 bytes magic
//	version           u8  (1)
//	kind              u8  (KindMain=1, KindPrior=2)
//	reserved          u16 (0)
//	metaLen           u32
//	meta              metaLen bytes of JSON (string keys; free-form)
//	nTensors          u32
//	per tensor:       u16 nameLen, name (utf-8), u8 ndim, ndim x u32 dims,
//	                  numel x float32 (row-major)
//	sha256            32 bytes over everything before it
//
// All integers and floats are little-endian. The trailing hash lets a loader
// reject a truncated or corrupted file.
const (
	KindMain  = 1
	KindPrior = 2
	tcwMagic  = "TCW1"
)

// Tensor is one named array in a weight file.
type Tensor struct {
	Name  string
	Shape []int
	Data  []float32
}

// WeightFile is the decoded form of a TCW1 file.
type WeightFile struct {
	Kind    uint8
	Meta    map[string]json.RawMessage
	Tensors []Tensor
}

// Encode writes the file.
func (w *WeightFile) Encode() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(tcwMagic)
	b.WriteByte(1)
	b.WriteByte(w.Kind)
	binary.Write(&b, binary.LittleEndian, uint16(0))
	meta, err := json.Marshal(w.Meta) // map keys are sorted: output is deterministic
	if err != nil {
		return nil, err
	}
	if w.Meta == nil {
		meta = []byte("{}")
	}
	binary.Write(&b, binary.LittleEndian, uint32(len(meta)))
	b.Write(meta)
	binary.Write(&b, binary.LittleEndian, uint32(len(w.Tensors)))
	for _, t := range w.Tensors {
		if numel(t.Shape) != len(t.Data) {
			return nil, fmt.Errorf("tensor %s: shape %v does not match %d values", t.Name, t.Shape, len(t.Data))
		}
		binary.Write(&b, binary.LittleEndian, uint16(len(t.Name)))
		b.WriteString(t.Name)
		b.WriteByte(byte(len(t.Shape)))
		for _, d := range t.Shape {
			binary.Write(&b, binary.LittleEndian, uint32(d))
		}
		for _, v := range t.Data {
			binary.Write(&b, binary.LittleEndian, math.Float32bits(v))
		}
	}
	sum := sha256.Sum256(b.Bytes())
	b.Write(sum[:])
	return b.Bytes(), nil
}

// DecodeWeights parses and verifies a TCW1 file.
func DecodeWeights(data []byte) (*WeightFile, error) {
	if len(data) < 12+32 {
		return nil, errors.New("weights: file too short")
	}
	body, sum := data[:len(data)-32], data[len(data)-32:]
	if h := sha256.Sum256(body); !bytes.Equal(h[:], sum) {
		return nil, errors.New("weights: checksum mismatch")
	}
	r := bytes.NewReader(body)
	var magic [4]byte
	io.ReadFull(r, magic[:])
	if string(magic[:]) != tcwMagic {
		return nil, errors.New("weights: bad magic")
	}
	var ver, kind uint8
	var rsv uint16
	var metaLen, n uint32
	rd := func(v any) error { return binary.Read(r, binary.LittleEndian, v) }
	if err := firstErr(rd(&ver), rd(&kind), rd(&rsv), rd(&metaLen)); err != nil {
		return nil, err
	}
	if ver != 1 {
		return nil, fmt.Errorf("weights: unsupported version %d", ver)
	}
	if int(metaLen) > r.Len() {
		return nil, errors.New("weights: bad meta length")
	}
	mb := make([]byte, metaLen)
	io.ReadFull(r, mb)
	w := &WeightFile{Kind: kind}
	if err := json.Unmarshal(mb, &w.Meta); err != nil {
		return nil, fmt.Errorf("weights: meta: %w", err)
	}
	if err := rd(&n); err != nil {
		return nil, err
	}
	for i := uint32(0); i < n; i++ {
		var nl uint16
		var nd uint8
		if err := firstErr(rd(&nl)); err != nil || int(nl) > r.Len() {
			return nil, errors.New("weights: truncated tensor header")
		}
		nb := make([]byte, nl)
		io.ReadFull(r, nb)
		if err := rd(&nd); err != nil {
			return nil, err
		}
		t := Tensor{Name: string(nb), Shape: make([]int, nd)}
		total := 1
		for k := range t.Shape {
			var d uint32
			if err := rd(&d); err != nil {
				return nil, err
			}
			t.Shape[k] = int(d)
			total *= int(d)
			if total < 0 || total > r.Len()/4+1 {
				return nil, errors.New("weights: tensor larger than file")
			}
		}
		if total*4 > r.Len() {
			return nil, errors.New("weights: truncated tensor data")
		}
		t.Data = make([]float32, total)
		raw := make([]byte, total*4)
		io.ReadFull(r, raw)
		for k := range t.Data {
			t.Data[k] = math.Float32frombits(binary.LittleEndian.Uint32(raw[k*4:]))
		}
		w.Tensors = append(w.Tensors, t)
	}
	if r.Len() != 0 {
		return nil, errors.New("weights: trailing bytes")
	}
	return w, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// Get returns the named tensor.
func (w *WeightFile) Get(name string) (Tensor, bool) {
	for _, t := range w.Tensors {
		if t.Name == name {
			return t, true
		}
	}
	return Tensor{}, false
}

// ToWeightFile snapshots the network (and caller-supplied meta).
func (n *Net) ToWeightFile(meta map[string]json.RawMessage) *WeightFile {
	w := &WeightFile{Kind: KindMain, Meta: meta}
	for _, s := range mainSpecs {
		w.Tensors = append(w.Tensors, Tensor{s.name, s.shape, append([]float32(nil), n.t[s.name]...)})
	}
	return w
}

// LoadWeightFile copies a file's tensors into the network, checking every
// name and shape.
func (n *Net) LoadWeightFile(w *WeightFile) error {
	if w.Kind != KindMain {
		return fmt.Errorf("weights: kind %d is not a main model", w.Kind)
	}
	for _, s := range mainSpecs {
		t, ok := w.Get(s.name)
		if !ok {
			return fmt.Errorf("weights: missing tensor %s", s.name)
		}
		if len(t.Shape) != len(s.shape) || numel(t.Shape) != numel(s.shape) {
			return fmt.Errorf("weights: tensor %s has shape %v, want %v", s.name, t.Shape, s.shape)
		}
		for i := range t.Shape {
			if t.Shape[i] != s.shape[i] {
				return fmt.Errorf("weights: tensor %s has shape %v, want %v", s.name, t.Shape, s.shape)
			}
		}
		copy(n.t[s.name], t.Data)
	}
	return nil
}
