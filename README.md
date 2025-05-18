# DraftKubeShadow

A Kubernetes security testing tool for analyzing and exploiting cluster security misconfigurations.

## Features

- **Sidecar Injection**: Inject containers into running pods via API or etcd
- **Kubelet Exploitation**: Interact with kubelet API endpoints
- **Reconnaissance**: Gather information about cluster and cloud configuration
- **RBAC Analysis**: Analyze and exploit RBAC misconfigurations

## Project Structure

```
DraftKubeShadow/
├── docs/               # Detailed documentation
│   ├── sidecarinject.md   # Sidecar injection module
│   ├── kubeletjack.md     # Kubelet exploitation module
│   ├── recon.md          # Reconnaissance module
│   └── rbac.md           # RBAC analysis module
├── modules/           # Command modules
├── pkg/              # Core packages
└── resources/        # Configs and templates
    ├── configs/      # Configuration files
    └── templates/    # JSON/YAML templates
```

## Quick Start

1. Clone the repository
2. Build the tool:
   ```bash
   go build -o kubeshadow
   ```
3. Run a module:
   ```bash
   ./kubeshadow <module-name> [flags]
   ```

## Available Modules

- [`sidecarinject`](docs/sidecarinject.md): Inject sidecar containers into pods
- [`kubeletjack`](docs/kubeletjack.md): Exploit kubelet API endpoints
- [`recon`](docs/recon.md): Perform cluster reconnaissance
- [`rbac`](docs/rbac.md): Analyze RBAC permissions

## Requirements

- Go 1.19 or higher
- Access to a Kubernetes cluster
- Appropriate permissions based on module

## Documentation

Each module has its own detailed documentation:
- [Sidecar Injection Guide](docs/sidecarinject.md)
- [Kubelet Exploitation Guide](docs/kubeletjack.md)
- [Reconnaissance Guide](docs/recon.md)
- [RBAC Analysis Guide](docs/rbac.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and security testing purposes only. Use responsibly and only on systems you have permission to test.