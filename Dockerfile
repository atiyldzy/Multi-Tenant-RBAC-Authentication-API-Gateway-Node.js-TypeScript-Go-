# Multi-stage Docker Build for Enterprise Auth & API Gateway

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json tsconfig.json ./
RUN npm ci

COPY src/ ./src
COPY openapi.json ./
RUN npm run build

# Stage 2: Runtime
FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --only=production

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/database/migrations ./dist/database/migrations
COPY --from=builder /app/openapi.json ./openapi.json

# Create keys directory with restricted permissions
RUN mkdir -p /app/keys && chown -R node:node /app

USER node

EXPOSE 4000

CMD ["node", "dist/server.js"]
