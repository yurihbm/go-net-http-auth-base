package api

const RequestContextDataKey string = "requestContextData"

type RequestContextData struct {
	UserUUID    string
	RequestUUID string
	Error       error
}
