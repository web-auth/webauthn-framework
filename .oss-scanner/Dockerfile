# Build of the OSS Scanner (https://github.com/anthropics/oss-scanner), with the repository root as context.
# It starts from the phpqa image the CI jobs run in, so phpunit-11 and the QA tools behave as they do on CI, and adds
# Node.js for the Stimulus tests. The scan runs without network access: every dependency is installed here.
# COMPOSER_ROOT_VERSION is set because Composer cannot guess the version without the Git metadata, and
# roave/security-advisories then conflicts with the packages this repository replaces.
FROM ghcr.io/spomky-labs/phpqa:8.4

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

ENV COMPOSER_ROOT_VERSION=5.4.x-dev

COPY . /src
WORKDIR /src

RUN composer install --no-interaction --no-progress \
    && npm install --no-audit --no-fund

RUN composer exec -- phpunit-11 --configuration .ci-tools/phpunit.xml.dist --no-progress \
    || echo "WARNING: PHPUnit reported failures"
RUN npm test || echo "WARNING: Jest reported failures"
