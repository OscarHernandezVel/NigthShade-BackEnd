# Build context: repository root (backend imports ../shared)
FROM node:22-alpine AS build
WORKDIR /app
COPY shared ./shared
COPY backend/package*.json ./backend/
RUN cd backend && npm ci
COPY backend ./backend
RUN cd backend && npm run build && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production DATA_DIR=/data PORT=4000
WORKDIR /app
COPY --from=build /app/backend/node_modules ./node_modules
COPY --from=build /app/backend/dist ./dist
COPY backend/package.json ./
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 4000
HEALTHCHECK CMD wget -qO- http://localhost:4000/api/health || exit 1
CMD ["node", "dist/server.js"]
