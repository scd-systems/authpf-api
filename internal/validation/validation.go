package validation

import (
	"fmt"
)

type ValidationError struct {
	HttpStatusCode int
	StatusCode     int
	Message        string
	Details        string
}

// Error implements the error interface for ValidationError
func (ve *ValidationError) Error() string {
	if ve.Details != "" {
		return fmt.Sprintf("%s: %s", ve.Message, ve.Details)
	}
	return ve.Message
}
