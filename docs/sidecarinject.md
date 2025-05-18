# Sidecar Injection Module

The sidecar injection module allows you to inject containers into running pods using either the Kubernetes API or direct etcd manipulation.

## Overview

This module supports two injection methods:
- **API Mode**: Uses the Kubernetes API server (recommended)
- **etcd Mode**: Direct manipulation of pod data in etcd (for bypassing API controls)

## Configuration

Create a sidecar configuration file in JSON format:

```json
{
    "name": "debug-sidecar",
    "image": "busybox:latest",
    "command": ["/bin/sh"],
    "args": ["-c", "while true; do sleep 30; done"],
    "env": [
        {
            "name": "POD_NAME",
            "valueFrom": {
                "fieldRef": {
                    "fieldPath": "metadata.name"
                }
            }
        }
    ]
}
```

Save as `resources/configs/sidecar_config.json`

## Usage Examples

### 1. API Mode (Recommended)

```bash
# Inject into a pod in default namespace
./kubeshadow sidecarinject \
    --mode=api \
    --pod=target-pod \
    --namespace=default \
    --config=resources/configs/sidecar_config.json

# Inject into a pod in custom namespace
./kubeshadow sidecarinject \
    --mode=api \
    --pod=target-pod \
    --namespace=custom-ns \
    --config=resources/configs/sidecar_config.json
```

### 2. etcd Mode

```bash
# Direct etcd injection
./kubeshadow sidecarinject \
    --mode=etcd \
    --endpoint=https://etcd:2379 \
    --cert=/path/to/cert.pem \
    --key=/path/to/key.pem \
    --ca=/path/to/ca.pem \
    --pod=target-pod \
    --namespace=default \
    --config=resources/configs/sidecar_config.json
```

## Parameters

### Common Parameters
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--mode` | Injection mode (`api` or `etcd`) | `api` |
| `--pod` | Target pod name | Required |
| `--namespace` | Pod namespace | `default` |
| `--config` | Sidecar config file path | Required |

### etcd Mode Parameters
| Parameter | Description | Required |
|-----------|-------------|----------|
| `--endpoint` | etcd HTTPS endpoint | Yes |
| `--cert` | TLS client certificate path | Yes |
| `--key` | TLS client key path | Yes |
| `--ca` | CA certificate path | Yes |

## Requirements

### API Mode
- Valid kubeconfig with sufficient permissions
- Network access to Kubernetes API server
- Permissions:
  ```yaml
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "update"]
  ```

### etcd Mode
- Direct access to etcd endpoint
- Valid TLS certificates
- Network access to etcd port (typically 2379)

## Security Considerations

1. API Mode:
   - Actions are logged in audit logs
   - Subject to RBAC controls
   - Safer for testing

2. etcd Mode:
   - Bypasses Kubernetes API controls
   - No audit trail in Kubernetes
   - Use with caution
   - Requires direct etcd access

## Troubleshooting

### Common Issues

1. API Mode:
   ```
   ❌ failed to update pod: pods "target-pod" is forbidden
   ```
   - Solution: Check RBAC permissions

2. etcd Mode:
   ```
   ❌ failed to retrieve pod from etcd
   ```
   - Solution: Verify etcd endpoint and certificates 