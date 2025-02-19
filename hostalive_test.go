package hostalive

import (
	"testing"
)

func TestHostAlive(t *testing.T) {
	hostAlive := NewHostAlive("192.168.3.0/24", false, 2, 100)

	results, err := hostAlive.HostAlive()
	if err != nil {
		t.Errorf("HostAlive should not return an error")
	}

	t.Log("results: ", len(results))
	total := 0
	for _, res := range results {
		if res.Alive == true {
			total += 1
		}
	}
	t.Log(total)
}
