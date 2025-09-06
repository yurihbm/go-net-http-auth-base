package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteJSONResponse_Success(t *testing.T) {
	w := httptest.NewRecorder()
	responseBody := ResponseBody[string]{
		Data:    "Test Data",
		Message: "Success",
	}

	WriteJSONResponse(w, http.StatusOK, responseBody)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ResponseBody[string]
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, responseBody.Data, response.Data)
	assert.Equal(t, responseBody.Message, response.Message)
}

func TestWriteJSONResponse_EncodingError(t *testing.T) {
	w := httptest.NewRecorder()
	responseBody := ResponseBody[chan int]{ // Using channel as a non-serializable type
		Data: nil,
	}

	WriteJSONResponse(w, http.StatusOK, responseBody)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]string
	err := json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Equal(t, "api.encoding_error", response["message"])
	assert.Contains(t, response["error"], "json: unsupported type")
}
