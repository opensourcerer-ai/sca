# SCA Makefile - install, test, lint

PREFIX ?= /opt/sca
INSTALL_DIR = $(PREFIX)
BIN_DIR = $(INSTALL_DIR)/bin
LIB_DIR = $(INSTALL_DIR)/lib

.PHONY: help install install-user test lint clean

help:
	@echo "SCA - Security Control Agent"
	@echo ""
	@echo "Targets:"
	@echo "  install         Install to $(PREFIX) (requires sudo if /opt/sca)"
	@echo "  install-user    Install to ~/.local/sca (no sudo required)"
	@echo "  test            Run test suite"
	@echo "  lint            Run shellcheck on scripts"
	@echo "  clean           Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX          Installation prefix (default: /opt/sca)"

install:
	@echo "Installing SCA to $(INSTALL_DIR)..."
	mkdir -p $(INSTALL_DIR)
	cp -r bin lib invariants prompts templates $(INSTALL_DIR)/
	cp README.md LICENSE ARCHITECTURE.md $(INSTALL_DIR)/
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
	@echo "Running tests..."
	bash tests/test_cli.sh
	bash tests/test_scope.sh
	@echo "All tests passed!"

lint:
	@echo "Running shellcheck..."
	shellcheck bin/*.sh lib/*.sh || true

clean:
	@echo "Cleaning build artifacts..."
	find . -name '*.tmp' -delete
	find . -name '.DS_Store' -delete
