package errors

import (
	"fmt"
	"kubeshadow/pkg/logger"
)

// ErrorType represents the type of error
type ErrorType string

const (
	// Configuration errors
	ErrConfig ErrorType = "CONFIG_ERROR"

	// Module errors
	ErrModule ErrorType = "MODULE_ERROR"

	// Kubernetes errors
	ErrK8s ErrorType = "K8S_ERROR"

	// Cloud provider errors
	ErrCloud ErrorType = "CLOUD_ERROR"

	// Validation errors
	ErrValidation ErrorType = "VALIDATION_ERROR"

	// Plugin errors
	ErrPlugin ErrorType = "PLUGIN_ERROR"

	// Runtime errors
	ErrRuntime ErrorType = "RUNTIME_ERROR"
)

// KubeShadowError represents a custom error type
type KubeShadowError struct {
	Type    ErrorType
	Message string
	Err     error
}

// Error implements the error interface
func (e *KubeShadowError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the wrapped error
func (e *KubeShadowError) Unwrap() error {
	return e.Err
}

// New creates a new KubeShadowError
func New(errType ErrorType, message string, err error) error {
	e := &KubeShadowError{
		Type:    errType,
		Message: message,
		Err:     err,
	}

	// Log the error
	logger.Error("%s", e.Error())

	return e
}

// IsConfigError checks if the error is a configuration error
func IsConfigError(err error) bool {
	if e, ok := err.(*KubeShadowError); ok {
		return e.Type == ErrConfig
	}
	return false
}

// IsModuleError checks if the error is a module error
func IsModuleError(err error) bool {
	if e, ok := err.(*KubeShadowError); ok {
		return e.Type == ErrModule
	}
	return false
}

// IsK8sError checks if the error is a Kubernetes error
func IsK8sError(err error) bool {
	if e, ok := err.(*KubeShadowError); ok {
		return e.Type == ErrK8s
	}
	return false
}

// IsValidationError checks if the error is a validation error
func IsValidationError(err error) bool {
	e, ok := err.(*KubeShadowError)
	return ok && e.Type == ErrValidation
}

// IsPluginError checks if the error is a plugin error
func IsPluginError(err error) bool {
	if e, ok := err.(*KubeShadowError); ok {
		return e.Type == ErrPlugin
	}
	return false
}

// IsRuntimeError checks if the error is a runtime error
func IsRuntimeError(err error) bool {
	if e, ok := err.(*KubeShadowError); ok {
		return e.Type == ErrRuntime
	}
	return false
}

// NewMultiError creates a new error that wraps multiple causes
func NewMultiError(errs []error) error {
	return &KubeShadowError{
		Type:    ErrRuntime,
		Message: "multiple errors occurred",
		Err:     errs[0], // Use first error as the main cause
	}
}
