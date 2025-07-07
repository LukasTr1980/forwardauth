FROM node:22-alpine AS deps

WORKDIR /app

COPY package.json package-lock.json* ./

RUN npm install

FROM node:22-alpine AS runner

WORKDIR /app

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=deps /app/node_modules ./node_modules

COPY --chown=appuser:appgroup . .

RUN chmod +x /app/docker-entrypoint.sh

USER appuser

EXPOSE 3000

ENTRYPOINT [ "/app/docker-entrypoint.sh" ]
CMD [ "npm", "run", "start" ]