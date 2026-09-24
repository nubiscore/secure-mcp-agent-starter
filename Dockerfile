# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json ./
# Only the server is built into the image. The dev issuer and the sample
# client are deliberately left out of production artifacts.
COPY src ./src
RUN pnpm exec tsc -p tsconfig.json && pnpm prune --prod

FROM node:22-alpine
ENV NODE_ENV=production
# Sane defaults for a container. Override with the ConfigMap mount in Kubernetes.
ENV TOOL_MANIFEST=/app/tools/manifest.yaml
ENV KILL_SWITCH_FILE=/app/config/kill-switch.json
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY tools ./tools
COPY deploy/k8s/kill-switch.json ./config/kill-switch.json
# Run as the unprivileged user the base image ships with. The Kubernetes
# manifests additionally enforce read-only root FS and dropped capabilities.
USER node
EXPOSE 3001
CMD ["node", "dist/src/index.js"]
