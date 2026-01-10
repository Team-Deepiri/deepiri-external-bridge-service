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

RUN apk add --no-cache curl dumb-init bash

# Copy K8s env loader scripts
COPY --chown=root:root shared/scripts/load-k8s-env.sh /usr/local/bin/load-k8s-env.sh
COPY --chown=root:root shared/scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/load-k8s-env.sh /usr/local/bin/docker-entrypoint.sh

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
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/bin/dumb-init", "--", "node", "dist/server.js"]
