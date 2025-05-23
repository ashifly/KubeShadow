package errors

import (
	"errors"
	"testing"
)

const (
	CONFIG_ERROR     ErrorType = "CONFIG_ERROR"
	MODULE_ERROR     ErrorType = "MODULE_ERROR"
	K8S_ERROR        ErrorType = "K8S_ERROR"
	CLOUD_ERROR      ErrorType = "CLOUD_ERROR"
	VALIDATION_ERROR ErrorType = "VALIDATION_ERROR"
)

func TestKubeShadowError(t *testing.T) {
	tests := []struct {
		name      string
		errType   ErrorType
		msg       string
		wrap      error
		expectStr string
	}{
		{
			name:      "Simple error",
			errType:   CONFIG_ERROR,
			msg:       "config failed",
			wrap:      nil,
			expectStr: "[CONFIG_ERROR] config failed",
		},
		{
			name:      "Wrapped error",
			errType:   MODULE_ERROR,
			msg:       "module failed",
			wrap:      errors.New("root cause"),
			expectStr: "[MODULE_ERROR] module failed: root cause",
		},
	}

	for _, tt := range tests {
		err := New(tt.errType, tt.msg, tt.wrap)
		if err.Error() != tt.expectStr {
			t.Errorf("%s: got %q, want %q", tt.name, err.Error(), tt.expectStr)
		}
		if e, ok := err.(*KubeShadowError); ok {
			if e.Type != tt.errType {
				t.Errorf("%s: got type %q, want %q", tt.name, e.Type, tt.errType)
			}
			if tt.wrap != nil && e.Unwrap().Error() != tt.wrap.Error() {
				t.Errorf("%s: wrapped error mismatch", tt.name)
			}
		}
	}
}

func TestErrorTypeChecking(t *testing.T) {
	errConfig := New(CONFIG_ERROR, "config", nil)
	errModule := New(MODULE_ERROR, "module", nil)
	errK8s := New(K8S_ERROR, "k8s", nil)
	errOther := errors.New("other")

	if !IsConfigError(errConfig) {
		t.Error("Expected IsConfigError to be true")
	}
	if !IsModuleError(errModule) {
		t.Error("Expected IsModuleError to be true")
	}
	if !IsK8sError(errK8s) {
		t.Error("Expected IsK8sError to be true")
	}
	if IsConfigError(errOther) || IsModuleError(errOther) || IsK8sError(errOther) {
		t.Error("Expected type checks to be false for regular error")
	}
}
