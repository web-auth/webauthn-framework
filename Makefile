#---Symfony-And-Docker-Makefile---------------#
# Author: https://github.com/yoanbernabeu
# License: MIT
#---------------------------------------------#

#---VARIABLES---------------------------------#
#---COMPOSER-#
COMPOSER = composer
COMPOSER_INSTALL = $(COMPOSER) install
COMPOSER_UPDATE = $(COMPOSER) update
#------------#

#---YARN-----#
YARN = yarn
YARN_INSTALL = $(YARN) install --force
YARN_UPDATE = $(YARN) update
YARN_BUILD = $(YARN) build
YARN_TEST = $(YARN) test
YARN_LINT = $(YARN) lint
YARN_CHECK_LINT = $(YARN) check-lint
YARN_FORMAT = $(YARN) format
YARN_CHECK_FORMAT = $(YARN) check-format
#------------#

#---QA Tools-----#
ECS_RUN = XDEBUG_MODE=off tools/vendor/bin/ecs
RECTOR_RUN = XDEBUG_MODE=off tools/vendor/bin/rector
DEPTRAC_RUN = XDEBUG_MODE=off tools/vendor/bin/deptrac
PHPSTAN_RUN = XDEBUG_MODE=off tools/vendor/bin/phpstan
INFECTION_RUN = tools/vendor/bin/infection
PARALLEL_LINT_RUN = XDEBUG_MODE=off tools/vendor/bin/parallel-lint
#------------#

#---PHPUNIT-#
PHPUNIT = APP_ENV=test tools/vendor/bin/simple-phpunit
#------------#
#---------------------------------------------#

## === 🆘  HELP ==================================================
help: ## Show this help.
	@echo "Makefile"
	@echo "---------------------------"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'
#---------------------------------------------#

## === 📦  COMPOSER ==============================================
composer-install: ## Install composer dependencies.
	$(COMPOSER_INSTALL)
.PHONY: composer-install

composer-install-tools: ## Install tools.
	cd tools
	$(COMPOSER_INSTALL)
	cd ..
.PHONY: composer-install-tools

composer-update: ## Update composer dependencies.
	$(COMPOSER_UPDATE)
	cd tools
	$(COMPOSER_UPDATE)
	cd ..
.PHONY: composer-update

composer-validate: ## Validate composer.json file.
	$(COMPOSER) validate
	cd tools
	$(COMPOSER) validate
	cd ..
.PHONY: composer-validate

composer-validate-deep: ## Validate composer.json and composer.lock files in strict mode.
	$(COMPOSER) validate --strict --check-lock
	cd tools
	$(COMPOSER) validate --strict --check-lock
	cd ..
.PHONY: composer-validate-deep
#---------------------------------------------#

## === 📦  YARN ===================================================
yarn-install: ## Install yarn dependencies.
	$(YARN_INSTALL)
.PHONY: yarn-install

yarn-update: ## Update yarn dependencies.
	$(YARN_UPDATE)
.PHONY: yarn-update

yarn-build: ## Build assets.
	$(YARN_BUILD)
.PHONY: yarn-build

yarn-test: ## Run tests.
	$(YARN_TEST)
.PHONY: yarn-test

yarn-lint: ## Lint files.
	$(YARN_LINT)
.PHONY: yarn-lint

yarn-check-lint: ## Check lint files.
	$(YARN_CHECK_LINT)
.PHONY: yarn-check-lint

yarn-format: ## Format files.
	$(YARN_FORMAT)
.PHONY: yarn-format

yarn-check-format: ## Check format files.
	$(YARN_CHECK_FORMAT)
.PHONY: yarn-check-format
#---------------------------------------------#

## === 🐛  QA =================================================
qa-parallel-lint: ## Check source code for syntax errors.
	$(PARALLEL_LINT_RUN) src/ tests/
.PHONY: qa-parallel-lint

qa-ecs-fix: ## Run ECS in fix mode.
	$(ECS_RUN) check --fix
.PHONY: qa-ecs-fix

qa-ecs-dry-run: ## Run ECS in dry-run mode.
	$(ECS_RUN) check
.PHONY: qa-ecs-dry-run

qa-phpstan: ## Run phpstan.
	$(PHPSTAN_RUN) analyse
.PHONY: qa-phpstan

qa-deptrac: ## Run deptrac.
	$(DEPTRAC_RUN) analyse --fail-on-uncovered --no-cache
.PHONY: qa-deptrac

qa-rector-dry-run: ## Run composer rector in dry-run mode.
	$(RECTOR_RUN) process --ansi --dry-run --xdebug
.PHONY: qa-rector-dry-run

qa-rector-fix: ## Run composer rector in fix mode.
	$(RECTOR_RUN) process
.PHONY: qa-rector-fix

qa-audit: ## Run composer audit.
	$(COMPOSER) audit
.PHONY: qa-audit
#---------------------------------------------#

## === 🔎  TESTS =================================================
tests: ## Run tests.
	$(PHPUNIT) --testdox --color
	$(YARN_TEST)
.PHONY: tests

tests-integration: ## Run integration tests.
	$(PHPUNIT) --testdox --color --group Integration
.PHONY: tests-integration

tests-unit: ## Run unit tests.
	$(PHPUNIT) --testdox --color --group Unit
.PHONY: tests-unit

tests-functional: ## Run functional tests.
	$(PHPUNIT) --testdox --color --group Functional
.PHONY: tests-functional

tests-coverage: ## Run tests with coverage.
	$(PHPUNIT) --coverage-html var/coverage
.PHONY: tests-coverage

tests-php: ## Run PHP tests.
	$(PHPUNIT) --testdox --color
.PHONY: tests-php

tests-yarn: ## Run Yarn tests.
	$(YARN_TEST)
.PHONY: tests-yarn

tests-infection: ## Run infection.
	$(INFECTION_RUN) -s --threads=$$(nproc) --min-msi=30 --min-covered-msi=50
.PHONY: tests-infection
#---------------------------------------------#

## === ⭐  OTHERS =================================================
before-commit: qa-rector-fix qa-ecs-fix qa-phpstan tests ## Run before commit.
.PHONY: before-commit

install: composer-install composer-install-tools yarn-install yarn-build ## First install.
.PHONY: install

#---------------------------------------------#

.DEFAULT_GOAL := help
