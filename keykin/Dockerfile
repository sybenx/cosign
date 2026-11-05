# The Keykin server (server/main.ts), mirroring the Cosign image: Node runs the TypeScript directly,
# uid 1000, and two volumes: /data for sealed records (may be snapshotted) and /keys for the key ring
# (never backed up, core §7.3). No relays, hosts or push gateways are built in: KEYKIN_RELAYS is required.
FROM node:24.15.0-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY runtime ./runtime
COPY server ./server
COPY frost-wasm ./frost-wasm
RUN mkdir -p /data /keys && chown 1000:1000 /data /keys && chmod 700 /keys
USER 1000:1000
ENV KEYKIN_DATA=/data KEYKIN_KEYS=/keys KEYKIN_BIND=0.0.0.0 KEYKIN_PORT=8711
EXPOSE 8711
CMD ["node", "server/main.ts"]
