# adjust to point to your local go-wrappers repo
DYLD_LIBRARY=../go-wrappers/includes/darwin/:$LD_LIBRARY_PATH
DYLD_LIBRARY_PATH=../go-wrappers/includes/darwin/:$LD_LIBRARY_PATH

.PHONY: up down build

up:
	@docker compose up -d --remove-orphans;

down:
	@docker compose down

build:
	@docker compose build;