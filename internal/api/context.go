package api

const RequestContextDataKey string = "requestContextData"

type RequestContextData struct {
	UserUUID  string
	RequestID string
	Error     error
}
