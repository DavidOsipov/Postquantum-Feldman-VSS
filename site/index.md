---
layout: default
title: Home
---

# PostQuantum-Feldman-VSS

A post-quantum secure implementation of Feldman's Verifiable Secret Sharing scheme.

## Overview

This project provides a robust implementation of Feldman's VSS (Verifiable Secret Sharing) scheme with post-quantum security considerations. It enables secure sharing and reconstruction of secrets across multiple parties.

## Features

- Post-quantum secure cryptographic primitives
- Threshold-based secret sharing
- Verification mechanisms for shares
- Compatible with modern Python environments

## Installation

```bash
pip install feldman-vss
```

## Quick Start

```python
from feldman_vss import create_shares, reconstruct_secret

# Generate shares
shares = create_shares(secret, total_shares, threshold)

# Reconstruct the secret
secret = reconstruct_secret(shares)
```

## Frequently Asked Questions

Please see the [FAQ](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/blob/main/docs/FAQ.md) for common questions and answers.

## Security

For security information, please refer to our [Security Policy](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/blob/main/SECURITY.md).

## Code of Conduct

Please review our [Code of Conduct](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/blob/main/CODE_OF_CONDUCT.md).

## Contributing

We welcome contributions! See our [Contributing Guide](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/blob/main/CONTRIBUTING.md).

## Documentation

For detailed documentation, please visit our [Documentation](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/blob/main/docs/DOCUMENTATION.md).

## License

This project is licensed under the terms found in the [LICENSE](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS/blob/main/LICENSE) file.