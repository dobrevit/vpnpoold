package worker

import (
	"errors"
	"math"
	"time"
)

type Random interface {
	Float64() float64
}

type Backoff struct {
	Minimum time.Duration
	Maximum time.Duration
	Jitter  float64
	Random  Random
}

func (b Backoff) Validate() error {
	if b.Minimum <= 0 {
		return errors.New("minimum backoff must be positive")
	}
	if b.Maximum < b.Minimum {
		return errors.New("maximum backoff must be greater than or equal to minimum")
	}
	if b.Jitter < 0 || b.Jitter > 1 {
		return errors.New("jitter must be between zero and one")
	}
	if b.Jitter != 0 && b.Random == nil {
		return errors.New("random source is required when jitter is enabled")
	}
	return nil
}

// Duration returns an exponentially increasing delay. Attempt zero is the
// minimum. Jitter is symmetric and the final result is always bounded by the
// configured minimum and maximum.
func (b Backoff) Duration(attempt uint) (time.Duration, error) {
	if err := b.Validate(); err != nil {
		return 0, err
	}
	delay := b.Minimum
	for index := uint(0); index < attempt && delay < b.Maximum; index++ {
		if delay > b.Maximum/2 {
			delay = b.Maximum
			break
		}
		delay *= 2
	}
	if delay > b.Maximum {
		delay = b.Maximum
	}
	if b.Jitter == 0 {
		return delay, nil
	}
	factor := 1 - b.Jitter + 2*b.Jitter*b.Random.Float64()
	jittered := time.Duration(math.Round(float64(delay) * factor))
	if jittered < b.Minimum {
		jittered = b.Minimum
	}
	if jittered > b.Maximum {
		jittered = b.Maximum
	}
	return jittered, nil
}
