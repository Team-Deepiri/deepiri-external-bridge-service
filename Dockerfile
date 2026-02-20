# Multi-stage build for External Bridge Service
# Supports both API (producer) and Worker (consumer) services

# Stage 1: Dependencies
FROM node:18-alpine AS dependencies
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --legacy-peer-deps --only=production

# Stage 2: Build source
FROM node:18-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json tsconfig.json ./
COPY src ./src

# Install all dependencies (including devDependencies for build)
RUN npm install --legacy-peer-deps

# Build TypeScript
RUN npm run build

# Stage 3: Production image (multi-purpose)
FROM node:18-alpine AS production
WORKDIR /app

RUN apk add --no-cache curl dumb-init bash

# Copy package files
COPY package.json package-lock.json ./

# Copy production dependencies
COPY --from=dependencies /app/node_modules ./node_modules

# Copy compiled JavaScript
COPY --from=builder /app/dist ./dist

# Create non-root user
RUN addgroup -g 1001 -S nodejs \
 && adduser -S nodejs -u 1001 \
 && chown -R nodejs:nodejs /app

USER nodejs

# Expose both API and Worker ports
EXPOSE 5006 5007

# Default: start API service
# Override with `npm run start:worker` for worker instances
CMD ["npm", "run", "start"]
