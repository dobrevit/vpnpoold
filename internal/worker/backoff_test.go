package worker

import (
	"testing"
	"time"
)

func TestBackoffExponentialAndBounded(t *testing.T) {
	backoff := Backoff{Minimum: time.Second, Maximum: 10 * time.Second}
	want := []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		10 * time.Second,
		10 * time.Second,
	}
	for attempt, expected := range want {
		got, err := backoff.Duration(uint(attempt))
		if err != nil {
			t.Fatal(err)
		}
		if got != expected {
			t.Fatalf("attempt %d = %v, want %v", attempt, got, expected)
		}
	}
	got, err := backoff.Duration(1000)
	if err != nil {
		t.Fatal(err)
	}
	if got != 10*time.Second {
		t.Fatalf("large attempt = %v", got)
	}
}

func TestBackoffJitterIsBounded(t *testing.T) {
	tests := []struct {
		random float64
		want   time.Duration
	}{
		{random: 0, want: 2 * time.Second},
		{random: .5, want: 4 * time.Second},
		{random: 1, want: 6 * time.Second},
	}
	for _, test := range tests {
		backoff := Backoff{
			Minimum: time.Second,
			Maximum: 10 * time.Second,
			Jitter:  .5,
			Random:  fixedRandom(test.random),
		}
		got, err := backoff.Duration(2)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("random %v = %v, want %v", test.random, got, test.want)
		}
	}
}

type fixedRandom float64

func (r fixedRandom) Float64() float64 {
	return float64(r)
}
