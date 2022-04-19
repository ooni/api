APP_ENV = development
DATABASE_URL?=postgresql://postgres@localhost:5432/ooni_measurements
VERSION = $(shell cat package.json \
  | grep version \
  | head -1 \
  | awk -F: '{ print $$2 }' \
  | sed 's/[",]//g' \
  | tr -d '[[:space:]]')

PWD = $(shell pwd)

.state/docker-build: Dockerfile
	docker-compose build --force-rm api

	mkdir -p .state
	touch .state/docker-build

serve: .state/docker-build
	docker-compose up --remove-orphans

build:
	@$(MAKE) .state/docker-build

initdb:
	docker-compose run --rm api python3 -m pytest --setup-only --create-db

tests: .state/docker-build
	docker-compose run --rm api python3 -m pytest $(T) $(TESTARGS)

.PHONY: build initdb tests serve
