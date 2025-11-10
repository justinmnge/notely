package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name: "valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key-123"},
			},
			expectedKey:   "my-secret-key-123",
			expectedError: "",
		},
		{
			name: "valid authorization header with complex key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123-def456-ghi789"},
			},
			expectedKey:   "abc123-def456-ghi789",
			expectedError: "",
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "empty authorization header value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key-123"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - only ApiKey without key value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - no space separator",
			headers: http.Header{
				"Authorization": []string{"ApiKeymy-secret-key-123"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - wrong case",
			headers: http.Header{
				"Authorization": []string{"apikey my-secret-key-123"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "authorization header with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey  my-secret-key-123"},
			},
			expectedKey:   "",
			expectedError: "",
		},
		{
			name: "authorization header with key containing spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey my secret key 123"},
			},
			expectedKey:   "my",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectedError != "" {
				if err == nil {
					t.Errorf("expected error '%s', got nil", tt.expectedError)
					return
				}
				if err.Error() != tt.expectedError {
					t.Errorf("expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got '%s'", err.Error())
					return
				}
			}

			if key != tt.expectedKey {
				t.Errorf("expected key '%s', got '%s'", tt.expectedKey, key)
			}
		})
	}
}

func TestGetAPIKey_ErrorTypes(t *testing.T) {
	t.Run("returns ErrNoAuthHeaderIncluded for missing header", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)

		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("returns generic error for malformed header", func(t *testing.T) {
		headers := http.Header{
			"Authorization": []string{"Bearer token"},
		}
		_, err := GetAPIKey(headers)

		if err == nil {
			t.Error("expected an error, got nil")
		}
		if err == ErrNoAuthHeaderIncluded {
			t.Error("expected generic error, got ErrNoAuthHeaderIncluded")
		}
	})
}
