# React frontend Dockerfile - Production Build
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy application code
COPY . .

# Build for production
RUN npm run build

# Production stage
FROM node:18-alpine

WORKDIR /app

# Install serve
RUN npm install -g serve

# Copy built files
COPY --from=builder /app/build ./build

# Copy start script
COPY start.sh ./
RUN chmod +x start.sh

# Expose port
EXPOSE 3000

# Start production server
ENTRYPOINT ["./start.sh"]
