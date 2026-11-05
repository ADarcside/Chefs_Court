FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src

RUN mkdir -p /app/uploads && chown -R node:node /app
USER node

EXPOSE 4000
CMD ["node", "src/server.js"]
