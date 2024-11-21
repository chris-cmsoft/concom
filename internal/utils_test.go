package internal

import (
	"errors"
	"reflect"
	"testing"
)

func TestOnError(t *testing.T) {
	t.Run("Callback_On_Error", func(t *testing.T) {
		// Should run the callback on error
		err := errors.New("test")
		didRun := false
		OnError(err, func(err error) {
			didRun = true
		})
		if didRun == false {
			t.Errorf("OnError() unexpectedly skipped callback function on populated error.")
		}
	})

	t.Run("No_Callback_On_Empty", func(t *testing.T) {
		// Should not run the callback if the error is nil
		OnError(nil, func(err error) {
			t.Errorf("OnError() unexpectedly invoked callback function on empty error.")
		})
	})
}

func TestSubtractSlice(t *testing.T) {
	tests := []struct {
		name     string
		left     []string
		right    []string
		expected []string
	}{
		{
			name:     "All Present in Right",
			left:     []string{"one", "two", "three"},
			right:    []string{"one", "two", "three"},
			expected: []string{},
		},
		{
			name:     "None Present in Right",
			left:     []string{"one", "two", "three"},
			right:    []string{},
			expected: []string{"one", "two", "three"},
		},
		{
			name:     "Some Present in Right",
			left:     []string{"one", "two", "three"},
			right:    []string{"one", "two"},
			expected: []string{"three"},
		},
		{
			name:     "Empty Left",
			left:     []string{},
			right:    []string{"one", "two"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SubtractSlice(tt.left, tt.right)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("SubtractSlice() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsOci(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected bool
	}{
		{
			name:     "Basic OCI prefixed url",
			source:   "oci://docker.io/library/alpine",
			expected: true,
		},
		{
			name:     "Basic OCI prefixed url with version",
			source:   "oci://docker.io/library/alpine:1.0",
			expected: true,
		},
		{
			name:     "Basic OCI url",
			source:   "docker.io/library/alpine",
			expected: true,
		},
		{
			name:     "Basic OCI url with protocol",
			source:   "https://docker.io/library/alpine",
			expected: true,
		},
		{
			name:     "Basic OCI url with version",
			source:   "docker.io/library/alpine:1.0",
			expected: true,
		},
		{
			name:     "Basic OCI url with latest tag",
			source:   "docker.io/library/alpine:latest",
			expected: true,
		},
		{
			name:     "Tar artifact",
			source:   "docker.io/library/alpine.tar.gz",
			expected: false,
		},
		{
			name:     "Tar artifact with https",
			source:   "https://docker.io/library/alpine.tar.gz",
			expected: false,
		},
		{
			name:     "Zip artifact",
			source:   "docker.io/library/alpine.zip",
			expected: false,
		},
		{
			name:     "Zip artifact with https",
			source:   "https://docker.io/library/alpine.zip",
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsOCI(tt.source); got != tt.expected {
				t.Errorf("isOciPlugin() = %v, want %v", got, tt.expected)
			}
		})
	}
}
