package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

type ResponseMeta struct {
	Total      int64   `json:"total,omitempty"`
	Limit      int     `json:"limit,omitempty"`
	NextCursor *string `json:"next_cursor,omitempty"`
}

type ResponseBody[T any] struct {
	Data    T                 `json:"data"`
	Message string            `json:"message,omitempty"`
	Meta    *ResponseMeta     `json:"meta,omitempty"`
	Error   string            `json:"error,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

func WriteJSONResponse[T any](w http.ResponseWriter, status int, body ResponseBody[T]) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(body)
	if err != nil {
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
