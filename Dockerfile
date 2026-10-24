# Production Dockerfile for Google Cloud Run
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy dependency files if any
COPY package*.json ./

# Install dependencies if present
RUN if [ -f package.json ]; then npm ci --only=production || true; fi

# Copy application source code
COPY . .

# Set environment defaults
ENV PORT=8080
ENV NODE_ENV=production

# Expose Cloud Run port
EXPOSE 8080

# Run the Scam Call Shield server
CMD ["node", "server.mjs"]
