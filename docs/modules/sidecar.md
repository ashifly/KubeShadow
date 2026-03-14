# Sidecar Module

The Sidecar Module is a core component of KubeShadow that enables the injection of sidecar containers into existing Kubernetes pods. This module is particularly useful for testing and development environments where you need to add monitoring, logging, or other auxiliary containers to your pods.

## Features

- **Multiple Injection Modes**: Support for both API and etcd-based injection
- **Secure Configuration**: Built-in security context and capability management
- **Flexible Configuration**: Support for environment variables, volume mounts, and more
- **Cleanup Support**: Automatic removal of injected sidecars

## Usage

### Basic Usage

```bash
kubeshadow sidecar --pod my-pod --namespace default --config sidecar-config.json
```

### Command Line Options

- `--mode`: Injection mode (api or etcd, default: api)
- `--pod`: Target pod name (required)
- `--namespace`: Target namespace (default: default)
- `--config`: Path to sidecar configuration file (required)

### Configuration File

The sidecar configuration is specified in JSON format:

```json
{
    "image": "nginx:latest",
    "command": ["nginx"],
    "args": ["-g", "daemon off;"],
    "env": [
        {
            "name": "NGINX_PORT",
            "value": "80"
        }
    ],
    "volumeMounts": [
        {
            "name": "config-volume",
            "mountPath": "/etc/nginx/conf.d"
        }
    ],
    "securityContext": {
        "runAsNonRoot": true,
        "runAsUser": 101,
        "runAsGroup": 101,
        "allowPrivilegeEscalation": false,
        "capabilities": {
            "drop": ["ALL"]
        },
        "readOnlyRootFilesystem": true
    }
}
```

#### Configuration Fields

- `image`: Container image to use (required)
- `command`: Command to run in the container
- `args`: Arguments to pass to the command
- `env`: Environment variables
- `volumeMounts`: Volume mounts for the container
- `securityContext`: Security settings for the container

## Security Considerations

The sidecar module implements several security best practices:

1. **Non-root Execution**: Sidecars run as non-root users
2. **Capability Restrictions**: All capabilities are dropped by default
3. **Read-only Filesystem**: Root filesystem is mounted as read-only
4. **Privilege Escalation Prevention**: Privilege escalation is disabled

## Examples

### Basic Sidecar

```json
{
    "image": "nginx:latest",
    "securityContext": {
        "runAsNonRoot": true,
        "runAsUser": 101
    }
}
```

### Monitoring Sidecar

```json
{
    "image": "prom/prometheus:latest",
    "command": ["prometheus"],
    "args": ["--config.file=/etc/prometheus/prometheus.yml"],
    "volumeMounts": [
        {
            "name": "prometheus-config",
            "mountPath": "/etc/prometheus"
        }
    ],
    "securityContext": {
        "runAsNonRoot": true,
        "runAsUser": 65534
    }
}
```

### Logging Sidecar

```json
{
    "image": "fluent/fluentd:latest",
    "volumeMounts": [
        {
            "name": "varlog",
            "mountPath": "/var/log"
        }
    ],
    "securityContext": {
        "runAsNonRoot": true,
        "runAsUser": 1000
    }
}
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure the service account has sufficient permissions
   - Check the security context settings

2. **Image Pull Failed**
   - Verify image name and tag
   - Check image pull secrets

3. **Pod Update Failed**
   - Ensure the pod is not in a terminating state
   - Check for conflicting container names

### Debugging

Enable debug logging to see detailed information:

```bash
kubeshadow --log-level debug sidecar --pod my-pod --config sidecar-config.json
```

## Best Practices

1. **Use Specific Image Tags**: Avoid using `latest` tag in production
2. **Implement Resource Limits**: Set CPU and memory limits
3. **Use Security Context**: Always specify security context
4. **Clean Up Sidecars**: Use the cleanup function when done
5. **Monitor Sidecar Health**: Implement health checks

## API Reference

### SidecarConfig

```go
type SidecarConfig struct {
    Image           string
    Command         []string
    Args            []string
    Env             []corev1.EnvVar
    VolumeMounts    []corev1.VolumeMount
    SecurityContext *corev1.SecurityContext
}
```

### Methods

- `Validate()`: Validates the module configuration
- `Execute(ctx)`: Runs the sidecar injection
- `Cleanup()`: Removes the injected sidecar 