FROM node:22-bookworm-slim AS dependencies
WORKDIR /app
COPY package*.json ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && npm ci --omit=dev \
    && rm -rf /root/.npm /var/lib/apt/lists/*

FROM node:22-bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium whois netbase \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY package*.json ./
COPY . .
ENV PORT=3000 CHROME_PATH=/usr/bin/chromium
VOLUME ["/app/data", "/app/screenshots"]
EXPOSE 3000
CMD ["npm", "start"]
