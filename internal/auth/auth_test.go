package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantKey   string
		wantError bool
	}{
		{
			name:      "valid api key",
			header:    "ApiKey mykey",
			wantKey:   "mykey",
			wantError: false,
		},
		{
			name:      "missing header",
			header:    "",
			wantKey:   "",
			wantError: true,
		},
		{
			name:      "wrong prefix",
			header:    "Bearer mykey",
			wantKey:   "",
			wantError: true,
		},
		{
			name:      "malformed single token",
			header:    "ApiKey",
			wantKey:   "",
			wantError: true,
		},
		{
			name:      "extra spaces still valid",
			header:    "ApiKey mykey extra",
			wantKey:   "mykey",
			wantError: false,
		},
		{
			name:      "case sensitive prefix",
			header:    "apikey mykey",
			wantKey:   "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			key, err := GetAPIKey(headers)

			if tt.wantError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, key)
			}
		})
	}
}
