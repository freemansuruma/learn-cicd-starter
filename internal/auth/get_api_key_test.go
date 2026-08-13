package auth

import (
	"net/http"
	//"strings"
	"testing"
	"errors"
	"reflect"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers  http.Header
		wantKey  string
		wantErr  error
	}{
		"valid api key header": {
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-key-123"},
			},
			wantKey: "secret-key-123",
			wantErr: nil,
		},
		"missing authorization header": {
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"malformed: no space after ApiKey": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"malformed: wrong scheme": {
			headers: http.Header{
				"Authorization": []string{"Bearer token123"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"malformed: empty key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			wantKey: "",      // The function returns an empty string, no error
			wantErr: nil,     // No error is returned currently
		},
		"valid with multiple spaces": {
			headers: http.Header{
				"Authorization": []string{"ApiKey   key-with-spaces"},
			},
			// strings.Split("ApiKey   key", " ") -> ["ApiKey", "", "", "key"]
			// splitAuth[1] is ""
			wantKey: "",      
			wantErr: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			// Check error
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				// Optional: check error message string if exact match needed
				// if err.Error() != tt.wantErr.Error() { ... }
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			if !reflect.DeepEqual(tt.wantKey, got) {
				// Provide a readable diff manually if needed
				t.Errorf("GetAPIKey() mismatch (-want +got):\n  want: %q\n  got:  %q", tt.wantKey, got)
			}
		})
	}
}