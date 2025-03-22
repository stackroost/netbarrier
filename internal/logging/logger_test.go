package logging

import "testing"

func TestNewLogger(t *testing.T) {
	_, err := NewLogger()
	if err != nil {
		t.Errorf("Failed to create logger: %v", err)
	}
}