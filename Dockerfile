FROM ghcr.io/team-deepiri/deepiri-base:18-alpine

COPY shared/deepiri-shared-utils/package*.json /shared/deepiri-shared-utils/
COPY shared/deepiri-shared-utils/tsconfig.json /shared/deepiri-shared-utils/
COPY shared/deepiri-shared-utils/src /shared/deepiri-shared-utils/src
# Copy service package files
COPY backend/deepiri-external-bridge-service/package*.json ./

# Install dependencies
RUN node -e "const fs=require('fs'),lock=JSON.parse(fs.readFileSync('package-lock.json'));delete lock.packages['../../shared/deepiri-shared-utils'];delete lock.packages['node_modules/@team-deepiri/shared-utils'];fs.writeFileSync('package-lock.json',JSON.stringify(lock));" \
 && cd /shared/deepiri-shared-utils \
 && npm ci --legacy-peer-deps \
 && node -e "const fs=require('fs'),p=JSON.parse(fs.readFileSync('package.json'));delete p.scripts.prepare;fs.writeFileSync('package.json',JSON.stringify(p,null,2));" \
 && rm -rf node_modules \
 && cd /app \
 && npm install --legacy-peer-deps \
 && cd /shared/deepiri-shared-utils \
 && npm ci --omit=dev --legacy-peer-deps \
 && cd /app \
 && npm cache clean --force

# Copy source
COPY backend/deepiri-external-bridge-service/tsconfig.json ./
COPY backend/deepiri-external-bridge-service/src ./src

# Build
RUN npm run build

RUN mkdir -p logs && chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 5006
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/bin/dumb-init", "--", "node", "dist/server.js"]
