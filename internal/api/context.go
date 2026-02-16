package api

type APIContextKey string

const RequestContextDataKey APIContextKey = "requestContextData"

type RequestContextData struct {
	UserUUID    string
	RequestUUID string
	Error       error
}
