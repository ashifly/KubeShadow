package sidecar

import (
	"context"
	"kubeshadow/pkg/errors"
	"testing"
)

func TestSidecarModule_Validate(t *testing.T) {
	tests := []struct {
		name      string
		pod       string
		config    string
		wantError bool
	}{
		{
			name:      "Valid configuration",
			pod:       "test-pod",
			config:    "test-config.json",
			wantError: false,
		},
		{
			name:      "Missing pod name",
			pod:       "",
			config:    "test-config.json",
			wantError: true,
		},
		{
			name:      "Missing config path",
			pod:       "test-pod",
			config:    "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := NewSidecarModule()

			// Set flags
			module.Command().Flags().Set("pod", tt.pod)
			module.Command().Flags().Set("config", tt.config)

			err := module.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}

			if err != nil && !errors.IsValidationError(err) {
				t.Errorf("Expected validation error, got %v", err)
			}
		})
	}
}

func TestSidecarModule_Execute(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		pod       string
		namespace string
		config    string
		wantError bool
	}{
		{
			name:      "Valid API mode",
			mode:      "api",
			pod:       "test-pod",
			namespace: "default",
			config:    "test-config.json",
			wantError: false,
		},
		{
			name:      "Valid etcd mode",
			mode:      "etcd",
			pod:       "test-pod",
			namespace: "default",
			config:    "test-config.json",
			wantError: false,
		},
		{
			name:      "Invalid mode",
			mode:      "invalid",
			pod:       "test-pod",
			namespace: "default",
			config:    "test-config.json",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := NewSidecarModule()

			// Set flags
			module.Command().Flags().Set("mode", tt.mode)
			module.Command().Flags().Set("pod", tt.pod)
			module.Command().Flags().Set("namespace", tt.namespace)
			module.Command().Flags().Set("config", tt.config)

			err := module.Execute(context.Background())
			if (err != nil) != tt.wantError {
				t.Errorf("Execute() error = %v, wantError %v", err, tt.wantError)
			}

			if err != nil && !errors.IsModuleError(err) {
				t.Errorf("Expected module error, got %v", err)
			}
		})
	}
}
