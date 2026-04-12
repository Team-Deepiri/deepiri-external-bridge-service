FROM node:18-alpine
WORKDIR /app

RUN apk add --no-cache curl dumb-init bash

# Copy K8s env loader scripts
COPY --chown=root:root scripts/load-k8s-env.sh /usr/local/bin/load-k8s-env.sh
COPY --chown=root:root scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/load-k8s-env.sh /usr/local/bin/docker-entrypoint.sh

# Copy service package files
COPY package.json ./
COPY package-lock.json ./
COPY .npmrc ./

# Install dependencies
RUN --mount=type=secret,id=github_token \
    { echo "@deepiri:registry=https://npm.pkg.github.com"; \
      echo "//npm.pkg.github.com/:_authToken=$(cat /run/secrets/github_token)"; \
    } > .npmrc && \
    npm ci --legacy-peer-deps && \
    npm cache clean --force && \
    echo "@deepiri:registry=https://npm.pkg.github.com" > .npmrc

# Copy source
COPY tsconfig.json ./
COPY src ./src

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
