package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

func getControllerArgs(method string, endpoint string, body any) (*httptest.ResponseRecorder, *http.Request) {
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, endpoint, bytes.NewBuffer(buf))
	w := httptest.NewRecorder()

	return w, req
}
