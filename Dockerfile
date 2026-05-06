# Use official Alpine Python image for minimal footprint (~50MB vs ~120MB slim)
FROM python:3.11-alpine

# Set working directory
WORKDIR /app

# Install dependencies first (leveraging Docker cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .

# HF Spaces automatically injects $PORT. 
# Our server reads it with a fallback to 7860.
ENV PORT=7860
EXPOSE 7860

# Start the async WebSocket server
CMD ["python", "server.py"]
