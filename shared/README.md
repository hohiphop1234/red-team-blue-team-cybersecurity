# Shared Utilities

This directory contains shared utilities and helper functions used by both Red Team and Blue Team tools.

## Utilities

- `utils.py` - Common utility functions (IP validation, hostname resolution, etc.)

## Usage

Both teams can import and use these utilities:

```python
from shared.utils import is_valid_ip, resolve_hostname, parse_port_range
```

