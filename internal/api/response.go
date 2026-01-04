package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type ResponseMeta struct {
	CurrentPage  int `json:"page,omitempty"`
	NextPage     int `json:"next_page,omitempty"`
	PreviousPage int `json:"previous_page,omitempty"`
	TotalPages   int `json:"total_pages,omitempty"`
	PageSize     int `json:"page_size,omitempty"`
	TotalItems   int `json:"total_items,omitempty"`
}

type ResponseBody[T any] struct {
	Data    T                 `json:"data"`
	Message string            `json:"message,omitempty"`
	Meta    *ResponseMeta     `json:"meta,omitempty"`
	Error   string            `json:"error,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// WriteJSONResponse writes a JSON response to the http.ResponseWriter with the
// given status code and body.
// It sets the "Content-Type" header to "application/json" and encodes the
// provided body as JSON.
// If encoding fails, it writes a minimal error response.
//
// Parameters:
//
//	w       - The http.ResponseWriter to write the response to.
//	status  - The HTTP status code to set in the response.
//	body    - The response body to encode as JSON.
//
// Type Parameters:
//
//	T - The type of the data in the response body.
func WriteJSONResponse[T any](w http.ResponseWriter, status int, body ResponseBody[T]) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(body)
	if err != nil {
		// Use a dedicated error response struct to ensure valid JSON.
		// This is safe and will not panic.
		errorResponse, _ := json.Marshal(ResponseBody[any]{
			Error: "api.encoding_error",
		})
		data = errorResponse
		status = http.StatusInternalServerError
	}
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		slog.Error("WriteJSONResponse failed", "error", err)
	}
}
