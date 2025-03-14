# proxy

This Python forward proxy implementation addresses all three use cases you mentioned:

### 1. To avoid state or institutional browsing restrictions
- Acts as an intermediary between your device and the internet
- Handles both HTTP and HTTPS (via the CONNECT method)
- Establishes a bidirectional tunnel for secure connections
- Can be hosted on any server with internet access, allowing you to bypass local network restrictions

### 2. To block access to certain content
- Supports regex-based domain blocking
- Shows a custom "Access Blocked" page when users try to access blocked sites
- Blocks are applied at the connection level, preventing any data exchange

### 3. To protect identity online
- Includes anonymization features when the `--anonymize` flag is used:
  - Removes referrer headers
  - Removes cookies
  - Standardizes user agent
  - Adds Do Not Track headers
  - Masks original IP address

### How to use it:

1. Basic usage:
```bash
python proxy.py
```

2. Block specific domains:
```bash
python proxy.py --block "facebook\.com" "twitter\.com"
```

3. Enable anonymization:
```bash
python proxy.py --anonymize
```

4. Run on a specific port:
```bash
python proxy.py --port 9000
```

5. Use SSL for encrypted connections:
```bash
python proxy.py --ssl --cert cert.pem --key key.pem
```

To use this proxy with your browser, you'll need to configure your browser's proxy settings to point to the IP address and port where this proxy is running.

