package model

import "sort"

// RareClass is the shared output class for programs with too little history.
const RareClass = 0

// Programs maps program identities to head A's output classes. Class ids are
// stable once assigned, because warm-started weights are tied to them.
type Programs struct {
	Names []string `json:"names"` // index = class; Names[0] is the rare class
	idx   map[string]int
}

func newPrograms() *Programs {
	p := &Programs{Names: []string{"<rare>"}}
	p.reindex()
	return p
}

func (p *Programs) reindex() {
	p.idx = make(map[string]int, len(p.Names))
	for i, n := range p.Names {
		if i > 0 {
			p.idx[n] = i
		}
	}
}

// Class returns the class for a program, or RareClass if it has none.
func (p *Programs) Class(name string) int {
	if c, ok := p.idx[name]; ok {
		return c
	}
	return RareClass
}

// assign gives classes to every program with at least minRecords samples that
// has none yet, most frequent first, while slots remain.
func (p *Programs) assign(counts map[string]int, minRecords int) {
	var names []string
	for n, c := range counts {
		if c >= minRecords {
			if _, ok := p.idx[n]; !ok {
				names = append(names, n)
			}
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	for _, n := range names {
		if len(p.Names) >= NumClasses {
			break
		}
		p.Names = append(p.Names, n)
		p.idx[n] = len(p.Names) - 1
	}
}

func (p *Programs) clone() *Programs {
	c := &Programs{Names: append([]string(nil), p.Names...)}
	c.reindex()
	return c
}
