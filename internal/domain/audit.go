package domain

import "context"

type AuditLog struct {
	UUID          string  `json:"uuid"`
	ActorUUID     *string `json:"actor_uuid,omitempty"`
	IPAddress     string  `json:"ip_address"`
	UserAgent     string  `json:"user_agent"`
	Action        string  `json:"action"`
	ResourceType  string  `json:"resource_type"`
	ResourceUUID  string  `json:"resource_uuid"`
	RequestUUID   string  `json:"request_uuid"`
	Changes       any     `json:"changes,omitempty"`
	Status        string  `json:"status"`
	FailureReason *string `json:"failure_reason,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

const (
	// Status
	AuditStatusSuccess = "SUCCESS"
	AuditStatusFailure = "FAILURE"

	// Actions
	AuditActionUserCreate = "USER_CREATE"
	AuditActionUserUpdate = "USER_UPDATE"
	AuditActionUserDelete = "USER_DELETE"
	AuditActionLogin      = "LOGIN"
	AuditActionOAuthLogin = "OAUTH_LOGIN"
	AuditActionLogout     = "LOGOUT"

	// Resources
	AuditResourceUser = "user"
	AuditResourceAuth = "auth"
)

type CreateAuditLogDTO struct {
	ActorUUID     *string
	IPAddress     string
	UserAgent     string
	Action        string
	ResourceType  string
	ResourceUUID  string
	RequestUUID   string
	Changes       any
	Status        string
	FailureReason *string
}

type ListAuditLogsDTO struct {
	Action       *string
	ResourceType *string
	Status       *string
	ActorUUID    *string
	Cursor       *string
	Limit        int
	StartDate    *int64
	EndDate      *int64
}

type AuditLogPage struct {
	Items      []AuditLog
	NextCursor *string
	Total      int64
}

type AuditService interface {
	Log(ctx context.Context, dto CreateAuditLogDTO) error
	List(ctx context.Context, dto ListAuditLogsDTO) (*AuditLogPage, error)
}

type AuditRepository interface {
	Create(ctx context.Context, log *AuditLog) error
	List(ctx context.Context, dto ListAuditLogsDTO) ([]AuditLog, int64, error)
}
