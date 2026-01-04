package domain

type NotFoundError struct {
	message string
}

func NewNotFoundError(message string) *NotFoundError {
	return &NotFoundError{message: message}
}

func (e *NotFoundError) Error() string {
	return e.message
}

var _ error = (*NotFoundError)(nil)

// ==========

type ValidationError struct {
	details map[string]string
	message string
}

func NewValidationError(message string, details map[string]string) *ValidationError {
	return &ValidationError{
		message: message,
		details: details,
	}
}

func (e *ValidationError) Details() map[string]string {
	return e.details
}

func (e *ValidationError) Error() string {
	return e.message
}

var _ error = (*ValidationError)(nil)

// ==========

type ConflictError struct {
	message string
}

func NewConflictError(message string) *ConflictError {
	return &ConflictError{message: message}
}

func (e *ConflictError) Error() string {
	return e.message
}

var _ error = (*ConflictError)(nil)

// ==========

type UnauthorizedError struct {
	message string
}

func NewUnauthorizedError(message string) *UnauthorizedError {
	return &UnauthorizedError{message: message}
}

func (e *UnauthorizedError) Error() string {
	return e.message
}

var _ error = (*UnauthorizedError)(nil)

// ==========

type InternalServerError struct {
	message string
}

func NewInternalServerError(message string) *InternalServerError {
	return &InternalServerError{message: message}
}

func (e *InternalServerError) Error() string {
	return e.message
}

var _ error = (*InternalServerError)(nil)
