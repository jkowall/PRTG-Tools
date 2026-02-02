.PHONY: lint format test verify help

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  lint    Run flake8 to check code style"
	@echo "  format  Run black to format code"
	@echo "  test    Run pytest for unit tests"
	@echo "  verify  Run both linting and tests"

lint:
	flake8 .

format:
	black .

test:
	pytest tests/

verify: lint test
