package shared

type ContextKey string

const RequestContextDataKey ContextKey = "requestContextData"

type RequestContextData struct {
	UserUUID    string
	RequestUUID string
	Error       error
}
