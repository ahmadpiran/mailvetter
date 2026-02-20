package proxy

import (
	"testing"
)

func TestRoundRobin(t *testing.T) {
	// 1. Setup
	list := []string{
		"http://1.1.1.1:8000",
		"http://2.2.2.2:8000",
	}

	// Pass 0 for dynamic limit, and false for SMTP proxying
	if err := Init(list, 0, false); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// 2. Verify Rotation
	p1 := Global.Next()
	if p1.Host != "1.1.1.1:8000" {
		t.Errorf("Expected 1.1.1.1, got %s", p1.Host)
	}

	p2 := Global.Next()
	if p2.Host != "2.2.2.2:8000" {
		t.Errorf("Expected 2.2.2.2, got %s", p2.Host)
	}

	p3 := Global.Next()
	if p3.Host != "1.1.1.1:8000" {
		t.Errorf("Expected 1.1.1.1 (loop back), got %s", p3.Host)
	}
}
