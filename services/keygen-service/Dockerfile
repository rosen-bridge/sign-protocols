FROM node:18.12

LABEL maintainer="rosen-bridge team <team@rosen.tech>"
LABEL description="Docker image for the keygen-service owned by rosen-bridge organization."
LABEL org.label-schema.vcs-url="https://github.com/rosen-bridge/keygen-service"

RUN adduser --disabled-password --home /app --uid 8080 --gecos "ErgoPlatform" ergo && \
    install -m 0740 -o ergo -g ergo -d /app/peer-dialer /app/logs /app/tss-api/logs /app/tss-api/home \
    && chown -R ergo:ergo /app/ && umask 0077
USER ergo

WORKDIR /app
COPY --chmod=700 --chown=ergo:ergo package-lock.json ./
COPY --chmod=700 --chown=ergo:ergo ./services/keygen-service/package.json ./
ADD --chmod=700 --chown=ergo:ergo ./patches/ ./patches/
RUN npx patch-package
RUN npm prune --production
RUN npm ci
COPY --chmod=700 --chown=ergo:ergo ./services/keygen-service .
RUN npm run build

ENV NODE_ENV=production
ENV SERVICE_PORT=8080
ENV TSS_HOME_ADDRESS="/app/tss-api/home"
ENV TSS_LOG_ADDRESS="/app/tss-api/logs"

EXPOSE 8080

ENTRYPOINT ["npm", "run", "start"]
