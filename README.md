# Zero Trust Engine

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange.svg)](CONTRIBUTING.md)

A comprehensive Zero Trust security implementation engine that provides continuous verification, microsegmentation, and policy-based access control for modern distributed systems.

## Features

- **Continuous Authentication**: Never trust, always verify - continuous identity validation
- **Microsegmentation**: Granular network segmentation and isolation
- **Policy Engine**: Flexible, context-aware access policies
- **Device Trust**: Verify device health and compliance before granting access
- **Least Privilege**: Enforce minimal necessary permissions
- **Audit Logging**: Complete audit trail of all access decisions

## Zero Trust Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Zero Trust Engine                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Identity    │  │  Device     │  │  Network    │        │
│  │  Provider   │  │  Trust      │  │  Access     │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│         │                │                │                 │
│         └────────────────┼────────────────┘                 │
│                          │                                  │
│                          ▼                                  │
│              ┌───────────────────────┐                      │
│              │    Policy Engine     │                      │
│              │  (Context-Aware)     │                      │
│              └───────────┬──────────┘                      │
│                          │                                  │
│         ┌────────────────┼────────────────┐                 │
│         │                │                │                 │
│         ▼                ▼                ▼                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Access     │  │  Micro-     │  │  Audit      │        │
│  │  Control    │  │  segment    │  │  Log        │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
zero-trust-engine/
├── src/
│   ├── engine/          # Core engine
│   │   ├── __init__.py
│   │   ├── core.py      # Main engine orchestrator
│   │   └── config.py    # Configuration management
│   ├── auth/            # Authentication modules
│   │   ├── __init__.py
│   │   ├── identity.py  # Identity verification
│   │   └── device.py    # Device trust validation
│   ├── policy/          # Policy engine
│   │   ├── __init__.py
│   │   ├── engine.py    # Policy evaluation
│   │   └── rules.py     # Policy rule definitions
│   └── microsegmentation/
│       ├── __init__.py
│       └── segment.py   # Network segmentation
├── cli.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .gitignore
```

## Installation

### From Source

```bash
git clone https://github.com/janderik/zero-trust-engine.git
cd zero-trust-engine
pip install -r requirements.txt
```

### Using Docker

```bash
docker build -t zero-trust-engine .
docker run -it zero-trust-engine
```

## Usage

### Initialize Engine

```python
from src.engine.core import ZeroTrustEngine

engine = ZeroTrustEngine()
engine.initialize()
```

### Evaluate Access Request

```python
from src.engine.core import AccessRequest

request = AccessRequest(
    user_id="user123",
    device_id="device456",
    resource="api/sensitive-data",
    action="read",
    source_ip="192.168.1.100"
)

decision = engine.evaluate(request)
print(f"Access: {decision.allowed}")
print(f"Reason: {decision.reason}")
```

### CLI Usage

```bash
# Start the engine
python cli.py start

# Evaluate a request
python cli.py evaluate --user user123 --resource api/data --action read

# Show current policies
python cli.py policies list

# Add a new policy
python cli.py policies add --rule "allow_user_data_access"
```

## Policy Examples

```yaml
# Example policy rules
policies:
  - name: "user_data_access"
    description: "Allow users to access their own data"
    conditions:
      - type: "identity"
        verified: true
      - type: "device"
        compliant: true
      - type: "resource"
        owner: "{{user_id}}"
    effect: "allow"
    
  - name: "admin_operations"
    description: "Restrict admin operations to trusted networks"
    conditions:
      - type: "identity"
        role: "admin"
        mfa_verified: true
      - type: "network"
        trusted: true
      - type: "time"
        business_hours: true
    effect: "allow"
```

## Configuration

Create a `config.yaml` file:

```yaml
engine:
  mode: "enforce"  # or "audit"
  log_level: "info"

identity:
  providers:
    - type: "local"
    - type: "ldap"
      url: "ldap://ldap.example.com"
    - type: "oauth2"
      issuer: "https://auth.example.com"

device:
  trust_score_threshold: 70
  require_compliance: true

network:
  segments:
    - name: "production"
      cidr: "10.0.1.0/24"
    - name: "development"
      cidr: "10.0.2.0/24"
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
