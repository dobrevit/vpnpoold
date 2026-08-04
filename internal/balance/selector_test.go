package balance

import "testing"

func TestWeightedRoundRobin(t *testing.T) {
	selector := &Selector{}
	candidates := []Candidate{
		{ID: "a", Address: "10.0.0.1:1081", Weight: 2, Healthy: true},
		{ID: "b", Address: "10.0.0.2:1081", Weight: 1, Healthy: true},
	}
	var got []string
	for index := 0; index < 6; index++ {
		selected, err := selector.Select(RoundRobin, "", candidates)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, selected.ID)
	}
	want := []string{"a", "a", "b", "a", "a", "b"}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("sequence = %v, want %v", got, want)
		}
	}
}

func TestWeightedLeastConnections(t *testing.T) {
	selector := &Selector{}
	candidates := []Candidate{
		{ID: "a", Address: "a:1", Weight: 1, ActiveConnections: 2, Healthy: true},
		{ID: "b", Address: "b:1", Weight: 4, ActiveConnections: 3, Healthy: true},
		{ID: "c", Address: "c:1", Weight: 1, ActiveConnections: 0, Healthy: false},
	}
	selected, err := selector.Select(LeastConnections, "", candidates)
	if err != nil {
		t.Fatal(err)
	}
	if selected.ID != "b" {
		t.Fatalf("selected = %q", selected.ID)
	}
}

func TestRendezvousRemovalOnlyMovesRemovedWorkersKeys(t *testing.T) {
	selector := &Selector{}
	all := []Candidate{
		{ID: "a", Address: "a:1", Weight: 1, Healthy: true},
		{ID: "b", Address: "b:1", Weight: 1, Healthy: true},
		{ID: "c", Address: "c:1", Weight: 1, Healthy: true},
	}
	remaining := []Candidate{all[0], all[2]}
	for index := 0; index < 1000; index++ {
		key := string(rune(index + 1))
		before, err := selector.Select(UsernameHash, key, all)
		if err != nil {
			t.Fatal(err)
		}
		after, err := selector.Select(UsernameHash, key, remaining)
		if err != nil {
			t.Fatal(err)
		}
		if before.ID != "b" && after.ID != before.ID {
			t.Fatalf("key %d moved from %s to %s even though selected worker remains", index, before.ID, after.ID)
		}
	}
}

func TestSelectorFailsClosed(t *testing.T) {
	selector := &Selector{}
	_, err := selector.Select(RoundRobin, "", []Candidate{
		{ID: "healthy-but-draining", Address: "a:1", Weight: 1, Healthy: true, Draining: true},
		{ID: "unhealthy", Address: "b:1", Weight: 1},
	})
	if err == nil {
		t.Fatal("Select() unexpectedly selected an unavailable worker")
	}
}
