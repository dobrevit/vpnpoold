package balance

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"sync/atomic"
)

type Mode string

const (
	RoundRobin       Mode = "round_robin"
	LeastConnections Mode = "least_connections"
	SourceHash       Mode = "source_hash"
	UsernameHash     Mode = "username_hash"
	SessionHash      Mode = "session_hash"
)

type Candidate struct {
	ID                string
	Address           string
	Weight            int
	ActiveConnections int64
	Healthy           bool
	Draining          bool
	Generation        uint64
}

type Selector struct {
	roundRobin atomic.Uint64
}

func (s *Selector) Select(mode Mode, key string, candidates []Candidate) (Candidate, error) {
	eligible, err := eligibleCandidates(candidates)
	if err != nil {
		return Candidate{}, err
	}
	switch mode {
	case RoundRobin:
		return s.roundRobinSelect(eligible), nil
	case LeastConnections:
		return leastConnectionsSelect(eligible), nil
	case SourceHash, UsernameHash, SessionHash:
		if key == "" {
			return Candidate{}, errors.New("hash selection key must not be empty")
		}
		return rendezvousSelect(key, eligible), nil
	default:
		return Candidate{}, errors.New("unsupported balancing mode")
	}
}

func eligibleCandidates(candidates []Candidate) ([]Candidate, error) {
	result := make([]Candidate, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if !candidate.Healthy || candidate.Draining {
			continue
		}
		if candidate.ID == "" || candidate.Address == "" || candidate.Weight <= 0 ||
			candidate.Weight > 100 || candidate.ActiveConnections < 0 {
			return nil, errors.New("eligible candidate has invalid ID, address, or weight")
		}
		if _, exists := seen[candidate.ID]; exists {
			return nil, errors.New("eligible candidate ID is duplicated")
		}
		seen[candidate.ID] = struct{}{}
		result = append(result, candidate)
	}
	if len(result) == 0 {
		return nil, errors.New("no healthy undrained workers are available")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *Selector) roundRobinSelect(candidates []Candidate) Candidate {
	var total uint64
	for _, candidate := range candidates {
		total += uint64(candidate.Weight)
	}
	position := (s.roundRobin.Add(1) - 1) % total
	for _, candidate := range candidates {
		weight := uint64(candidate.Weight)
		if position < weight {
			return candidate
		}
		position -= weight
	}
	panic("unreachable weighted round-robin position")
}

func leastConnectionsSelect(candidates []Candidate) Candidate {
	selected := candidates[0]
	for _, candidate := range candidates[1:] {
		left := float64(candidate.ActiveConnections) / float64(candidate.Weight)
		right := float64(selected.ActiveConnections) / float64(selected.Weight)
		if left < right {
			selected = candidate
		}
	}
	return selected
}

func rendezvousSelect(key string, candidates []Candidate) Candidate {
	selected := candidates[0]
	selectedScore := weightedRendezvousScore(key, selected)
	for _, candidate := range candidates[1:] {
		score := weightedRendezvousScore(key, candidate)
		if score < selectedScore {
			selected = candidate
			selectedScore = score
		}
	}
	return selected
}

func weightedRendezvousScore(key string, candidate Candidate) float64 {
	digest := sha256.Sum256([]byte(key + "\x00" + candidate.ID))
	raw := binary.BigEndian.Uint64(digest[:8])
	// Map into (0,1), then use the standard weighted rendezvous exponential
	// race. The lowest score wins.
	uniform := (float64(raw) + 1) / (float64(math.MaxUint64) + 2)
	return -math.Log(uniform) / float64(candidate.Weight)
}
