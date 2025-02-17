package hostalive

import (
	"testing"
)

func TestHostAlive(t *testing.T) {
	hostAlive := NewHostAlive("192.168.1.0/24", false, 2, 100)

	results, err := hostAlive.HostAlive()
	if err != nil {
		t.Errorf("HostAlive should not return an error")
	}

	t.Log("results: ", results)

}
