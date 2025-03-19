---
layout: libdoc/page
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

## Documentation & Resources

- [Detailed Documentation](/docs/DOCUMENTATION)
- [Frequently Asked Questions](/docs/FAQ)
- [Security Policy](/SECURITY)
- [Code of Conduct](/CODE_OF_CONDUCT)
- [Contributing Guide](/CONTRIBUTING)
- [License](/LICENSE)

## View on GitHub

The complete source code is available on [GitHub](https://github.com/DavidOsipov/PostQuantum-Feldman-VSS).