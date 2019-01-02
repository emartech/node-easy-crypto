.PHONY: test

test:
	docker-compose run --rm app npm test
