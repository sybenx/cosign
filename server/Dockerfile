# The Cosign server, for running beside a relay (deploy/ shows it next to syb.lol's
# Ditto). One container is one member of one group; its state lives in /data/<a|b>.
#
# On first start it makes a throwaway key in /data (start.sh); after that it runs as A.
FROM node:24.15.0-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY *.ts start.sh ./
# uid 1000 is "node" here, and owns the data directory on the host.
USER 1000:1000
ENV HOST=0.0.0.0
EXPOSE 8711
CMD ["./start.sh"]
