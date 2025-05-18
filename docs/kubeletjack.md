# Kubelet Exploitation Module

The kubelet exploitation module allows you to interact with kubelet API endpoints to gather information and execute commands in containers.

## Overview

This module provides capabilities to:
- List pods running on a node
- Execute commands in containers
- Read container logs
- Access container file system
- Retrieve pod and container information

## Usage Examples

### List Pods on Node
```bash
./kubeshadow kubeletjack list-pods \
    --node-ip=10.0.0.10 \
    --port=10250
```

### Execute Command in Container
```bash
./kubeshadow kubeletjack exec \
    --node-ip=10.0.0.10 \
    --port=10250 \
    --namespace=default \
    --pod=target-pod \
    --container=main \
    --command="ls -la"
```

### Get Container Logs
```bash
./kubeshadow kubeletjack logs \
    --node-ip=10.0.0.10 \
    --port=10250 \
    --namespace=default \
    --pod=target-pod \
    --container=main
```

## Parameters

### Common Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--node-ip` | Target node IP address | Required |
| `--port` | Kubelet port | 10250 |
| `--namespace` | Pod namespace | default |
| `--pod` | Target pod name | Required* |
| `--container` | Target container name | Required* |

*Required for exec and logs commands

### Command-specific Parameters
| Command | Parameter | Description |
|---------|-----------|-------------|
| `exec` | `--command` | Command to execute |
| `logs` | `--tail` | Number of lines to show |
| `logs` | `--follow` | Stream logs in real-time |

## Requirements

- Network access to kubelet port (typically 10250)
- One of the following conditions:
  - Anonymous kubelet API access enabled
  - Valid kubelet client certificates
  - Compromised node credentials

## Security Considerations

1. Authentication Methods:
   - Anonymous access (if enabled)
   - Client certificate authentication
   - Token authentication

2. Detection Risks:
   - Direct kubelet access may trigger alerts
   - Command execution is logged
   - File system access is audited

## Troubleshooting

### Common Issues

1. Connection Failed:
   ```
   ❌ failed to connect to kubelet: connection refused
   ```
   - Solution: Verify node IP and port
   - Check network connectivity
   - Ensure kubelet API is enabled

2. Authentication Failed:
   ```
   ❌ unauthorized: not allowed
   ```
   - Solution: Check authentication method
   - Verify certificates if using TLS
   - Check if anonymous access is enabled

3. Command Execution Failed:
   ```
   ❌ failed to exec command: container not found
   ```
   - Solution: Verify pod and container names
   - Check if container is running 