package daemon

import (
	"crypto/rand"
	"encoding/binary"
)

type cryptoRandom struct{}

func (cryptoRandom) Float64() float64 {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0.5
	}
	const mask = uint64(1)<<53 - 1
	return float64(binary.BigEndian.Uint64(raw[:])&mask) / float64(uint64(1)<<53)
}
