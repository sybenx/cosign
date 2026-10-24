# The Cosign server, for running beside a relay (deploy/ shows it next to syb.lol's
# Ditto). One container is one shared server: its own host key in /data/host.json, a
# group per directory (/data/a as setup.ts makes it, /data/groups/<id> for each one a
# device enrolls), all in one process.
#
# On first start, with no group at all, it makes a throwaway key in /data (start.sh) and
# serves it as A, beside whatever gets enrolled later.
FROM node:24.15.0-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY *.ts start.sh ./
COPY core ./core
COPY frost-wasm ./frost-wasm
# uid 1000 is "node" here, and owns the data directory on the host.
USER 1000:1000
ENV HOST=0.0.0.0
EXPOSE 8711
CMD ["./start.sh"]
