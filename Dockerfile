# syntax=docker/dockerfile:1
FROM node:20-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json ./
COPY src ./src
COPY dev ./dev
COPY examples ./examples
RUN pnpm build && pnpm prune --prod

FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY tools ./tools
# Run as the unprivileged user the base image ships with. The Kubernetes
# manifests additionally enforce read-only root FS and dropped capabilities.
USER node
EXPOSE 3001
CMD ["node", "dist/src/index.js"]
