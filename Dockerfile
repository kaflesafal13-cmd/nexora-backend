FROM node:22-slim
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
# The database lives in /data. Mount a persistent volume there, or balances are lost on redeploy.
ENV NODE_ENV=production DB_FILE=/data/nexora.db COOKIE_SECURE=true TRUST_PROXY=true
EXPOSE 3000
CMD ["node", "server.js"]
