# Build native dependencies and compile with the same Node major used in CI.
FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig*.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production PORT=4001
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/package.json ./package.json
USER node
EXPOSE 4001
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/v1/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
