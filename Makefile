# SCA Makefile - install, test, lint

PREFIX ?= /opt/sca
INSTALL_DIR = $(PREFIX)
BIN_DIR = $(INSTALL_DIR)/bin
LIB_DIR = $(INSTALL_DIR)/lib

.PHONY: help install install-user test test-unit test-integration test-all lint clean version

help:
	@echo "SCA - Security Control Agent v$(shell cat VERSION 2>/dev/null || echo 'unknown')"
	@echo ""
	@echo "Installation Targets:"
	@echo "  install         Install to $(PREFIX) (requires sudo if /opt/sca)"
	@echo "  install-user    Install to ~/.local/sca (no sudo required)"
	@echo ""
	@echo "Testing Targets:"
	@echo "  test            Run all tests (unit + integration)"
	@echo "  test-unit       Run unit tests only"
	@echo "  test-integration Run integration tests only"
	@echo "  test-all        Run all tests with verbose output"
	@echo "  lint            Run shellcheck on scripts"
	@echo ""
	@echo "Utility Targets:"
	@echo "  clean           Remove build artifacts"
	@echo "  version         Show version information"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX          Installation prefix (default: /opt/sca)"

install:
	@echo "Installing SCA to $(INSTALL_DIR)..."
	mkdir -p $(INSTALL_DIR)
	cp -r bin lib invariants prompts templates config $(INSTALL_DIR)/
	cp README.md LICENSE ARCHITECTURE.md VERSION $(INSTALL_DIR)/
	chmod +x $(BIN_DIR)/*
	@echo ""
	@echo "Installation complete!"
	@echo "Add $(BIN_DIR) to your PATH or symlink $(BIN_DIR)/sca to /usr/local/bin/sca"
	@echo ""
	@echo "To make agent read-only:"
	@echo "  sudo chown -R root:root $(INSTALL_DIR)"
	@echo "  sudo chmod -R a-w $(INSTALL_DIR)"

install-user:
	@$(MAKE) install PREFIX=~/.local/sca

test:
	@echo "Running all tests..."
	@chmod +x tests/run_tests.sh
	@chmod +x tests/unit/*.sh
	@chmod +x tests/integration/*.sh
	@./tests/run_tests.sh

test-unit:
	@echo "Running unit tests..."
	@chmod +x tests/run_tests.sh
	@chmod +x tests/unit/*.sh
	@./tests/run_tests.sh --unit-only

test-integration:
	@echo "Running integration tests..."
	@chmod +x tests/run_tests.sh
	@chmod +x tests/integration/*.sh
	@./tests/run_tests.sh --integration-only

test-all:
	@echo "Running all tests (verbose)..."
	@chmod +x tests/run_tests.sh
	@chmod +x tests/unit/*.sh
	@chmod +x tests/integration/*.sh
	@./tests/run_tests.sh --verbose

lint:
	@echo "Running shellcheck on all shell scripts..."
	@find bin/ lib/ tests/ -name "*.sh" -type f | while read -r script; do \
		echo "Checking: $$script"; \
		shellcheck "$$script" || exit 1; \
	done
	@echo "All scripts passed shellcheck!"

version:
	@cat VERSION

clean:
	@echo "Cleaning build artifacts and test fixtures..."
	find . -name '*.tmp' -delete
	find . -name '.DS_Store' -delete
	find tests/fixtures/ -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete!"
