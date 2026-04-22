FROM ghcr.io/team-deepiri/deepiri-base:18-alpine

# Copy service package files
COPY package.json ./
COPY package-lock.json ./
COPY .npmrc ./

# Install dependencies
RUN --mount=type=secret,id=github_token \
    { echo "@team-deepiri:registry=https://npm.pkg.github.com"; \
      echo "//npm.pkg.github.com/:_authToken=$(cat /run/secrets/github_token)"; \
    } > .npmrc && \
    npm ci --legacy-peer-deps && \
    npm cache clean --force && \
    echo "@team-deepiri:registry=https://npm.pkg.github.com" > .npmrc

# Copy source
COPY tsconfig.json ./
COPY src ./src

# Build
RUN npm run build

RUN mkdir -p logs && chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 5006
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/bin/dumb-init", "--", "node", "dist/server.js"]
