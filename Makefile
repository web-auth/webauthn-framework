.PHONY: mu
mu: vendor ## Mutation tests
	vendor/bin/infection -s --threads=$(nproc) --min-msi=23 --min-covered-msi=45
	vendor/bin/phpunit --coverage-text

.PHONY: tests
tests: vendor ## Run all tests
	vendor/bin/phpunit  --color

.PHONY: code-coverage-html
cc: vendor ## Show test coverage rates (HTML)
	vendor/bin/phpunit --coverage-html ./build

.PHONY: cs
cs: vendor ## Fix all files using defined ECS rules
	vendor/bin/ecs check --fix

.PHONY: tu
tu: vendor ## Run only unit tests
	vendor/bin/phpunit --color --group Unit

.PHONY: ti
ti: vendor ## Run only integration tests
	vendor/bin/phpunit --color --group Integration

.PHONY: tf
tf: vendor ## Run only functional tests
	vendor/bin/phpunit --color --group Functional

.PHONY: st
st: vendor ## Run static analyse
	vendor/bin/phpstan analyse


################################################

.PHONY: ci-mu
ci-mu: vendor ## Mutation tests (for Github only)
	vendor/bin/infection --logger-github -s --threads=$(nproc) --min-msi=23 --min-covered-msi=45

.PHONY: ci-cc
ci-cc: vendor ## Show test coverage rates (console)

.PHONY: ci-cs
ci-cs: vendor ## Check all files using defined ECS rules
	vendor/bin/ecs check

################################################


vendor: composer.json composer.lock
	composer validate
	composer install
.PHONY: rector
rector: vendor ## Check all files using Rector
	vendor/bin/rector process --ansi --dry-run --xdebug

.DEFAULT_GOAL := help
help:
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'
.PHONY: help
