# Sibna Python SDK

This is the Python SDK for the Sibna Protocol - a secure end-to-end encrypted messaging protocol.

## Building from Source

This SDK is self-contained and can be built independently.

### Prerequisites

- Rust toolchain (1.70+)
- Python 3.8+
- pip

### Build Steps

1. Build the Rust core library:
```bash
cd core
cargo build --release
```

2. Install the Python package:
```bash
cd ..
pip install -e .
```

## Usage

```python
from sibna import Client

# Create a client
client = Client(user_id="alice", server_url="http://localhost:8000")

# Register with the server
client.register()

# Send a message
client.send("bob", "Hello, Bob!")

# Start the background worker
client.start()
```

## Testing

Run the core library tests:
```bash
cd core
cargo test
```

## License

Apache-2.0 OR MIT
