# Configuration file for Jupyter Server (which Voila runs on)

# Get the configuration object
c = get_config()

# Force the server to listen on all network interfaces (0.0.0.0).
# This allows Docker to forward connections into the container.
c.ServerApp.ip = '0.0.0.0'

# Ensure the port is set correctly
c.ServerApp.port = 8866

# Do not attempt to open a browser inside the container
c.ServerApp.open_browser = False

# Allow the server to be accessed from external hosts (like the Windows host)
c.ServerApp.allow_remote_access = True