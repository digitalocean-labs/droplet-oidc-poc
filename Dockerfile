FROM golang:1.25 AS caddy

RUN set -x && \
  go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest && \
  xcaddy build --with=github.com/aksdb/caddy-cgi/v2 && \
  mv caddy /usr/bin/caddy


FROM node:lts-alpine AS statusphere

ARG STATUSPHERE_GIT_COMMIT_SHA="e4721616df50cd317c198f4c00a4818d5626d4ce"

WORKDIR /statusphere-example-app
COPY scripts/patches/statusphere-example-app/ _patches/

RUN set -x \
  && apk add --no-cache git python3 py3-pip make gcc g++ \
  && export TARGET_DIR=/statusphere-example-app \
  && export TARGET_REPO_URL=https://github.com/bluesky-social/statusphere-example-app.git \
  && export TARGET_COMMIT="${STATUSPHERE_GIT_COMMIT_SHA}" \
  && mkdir -p "${TARGET_DIR}" \
  && cd "${TARGET_DIR}" \
  && git init \
  && git remote add origin "${TARGET_REPO_URL}" \
  && git fetch origin "${TARGET_COMMIT}" --depth 1 \
  && git reset --hard "${TARGET_COMMIT}" \
  && rm -rf .git \
  && cat _patches/*.patch | git apply \
  && mv -v _patches/*.js ./ \
  && npm install \
  && npm run build

FROM python:3.12-alpine

COPY --from=caddy /usr/bin/caddy /usr/bin/caddy

COPY --from=statusphere /statusphere-example-app /statusphere-example-app

RUN set -x \
  && apk --no-cache add \
       ca-certificates \
       git \
       git-daemon \
       openssh-keygen \
       nodejs \
       openssl \
  && python -m pip install --no-cache uv \
  && uv venv /app-venv

ENV PORT=8080
ENV VIRTUAL_ENV=/app-venv

COPY Caddyfile /app/Caddyfile

COPY . /app-src
WORKDIR /app-src
RUN uv pip install /app-src

# Modify the Caddyfile for App Platform, TLS not needed since it proxies
RUN set -x && \
  sed -i \
    -e 's/{\$THIS_ENDPOINT}/http:\/\//g' \
    -e 's/{env.PYTHON}/\/app-venv\/bin\/python/g' \
    -e '/.*ACME_EMAIL.*/d' \
    /app/Caddyfile && \
  caddy fmt --overwrite /app/Caddyfile && \
  cat /app/Caddyfile

CMD ["sh", "-xe", "/app-src/scripts/entrypoint.sh"]
