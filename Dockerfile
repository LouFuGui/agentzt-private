FROM node:22-slim

WORKDIR /app

ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY config ./config
COPY src ./src
COPY examples ./examples
COPY scripts ./scripts

EXPOSE 8700 8787

CMD ["npm", "run", "gateway"]
