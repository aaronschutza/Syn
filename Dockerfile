# Start from a standard, slim Python base image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file (which includes voila, ipykernel, ipympl, etc.)
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# --- The Tornado downgrade line has been removed from here ---
# It is no longer needed and may hinder WebSocket compatibility.

# Explicitly register the Python kernel specification so Jupyter/Voila can find it.
RUN python -m ipykernel install --user --name python3 --display-name "Python 3 (ipykernel)"

# Copy the simulation notebook (which now contains the thread-safe update)
COPY Synergeia_Simulation.ipynb .

# Expose the port
EXPOSE 8866

# Command to run Jupyter Server configured for Voila
CMD ["jupyter", "server", \
     # Bind to all interfaces (0.0.0.0)
     "--ip=0.0.0.0", \
     "--port=8866", \
     "--no-browser", \
     # Allow running as root inside the container
     "--allow-root", \
     # Disable authentication tokens (using the updated syntax for Jupyter Server 2.0+)
     "--IdentityProvider.token=''", \
     "--IdentityProvider.password=''", \
     # Configure the server to automatically redirect the main URL to the Voila rendering
     "--ServerApp.default_url=/voila/render/Synergeia_Simulation.ipynb" \
]