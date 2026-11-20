import os

# CSV storage
CSV_FILE = os.path.join(os.path.dirname(__file__), "data.csv")

# Monitoring configuration
COLLECTION_INTERVAL = 5  # seconds
MAX_SECURITY_EVENTS = 500

# Network monitoring
NETWORK_TARGET = "8.8.8.8"

# Application monitoring
APPLICATION_BASE_URL = "http://localhost:8000"

# Enable/disable collectors
ENABLE_WINDOWS_LOGS = True
ENABLE_LINUX_LOGS = False
ENABLE_NETWORK_QUALITY = True
ENABLE_APPLICATION_MONITORING = True

# Linux authentication log
LINUX_AUTH_LOG = "/var/log/auth.log"