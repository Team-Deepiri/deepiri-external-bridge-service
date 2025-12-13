# Build shared-utils
FROM node:18-alpine AS shared-utils-builder
WORKDIR /shared-utils

COPY shared/deepiri-shared-utils/package.json ./
COPY shared/deepiri-shared-utils/package-lock.json ./
COPY shared/deepiri-shared-utils/tsconfig.json ./
COPY shared/deepiri-shared-utils/src ./src

RUN npm install --legacy-peer-deps \
 && npm run build

# ------------------------------

FROM node:18-alpine
WORKDIR /app

RUN apk add --no-cache curl dumb-init

# Copy service package files
COPY backend/deepiri-external-bridge-service/package.json ./
COPY backend/deepiri-external-bridge-service/package-lock.json ./

# Copy built shared-utils
COPY --from=shared-utils-builder /shared-utils /shared-utils

# SINGLE install step (this is the fix)
RUN npm install --legacy-peer-deps file:/shared-utils \
 && npm cache clean --force

# Copy source
COPY backend/deepiri-external-bridge-service/tsconfig.json ./
COPY backend/deepiri-external-bridge-service/src ./src

# Build
RUN npm run build

# Runtime user
RUN addgroup -g 1001 -S nodejs \
 && adduser -S nodejs -u 1001 \
 && chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 5006
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/server.js"]
