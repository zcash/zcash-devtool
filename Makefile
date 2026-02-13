# Simple wrapper for scripts with printed status messages.
# 
# Running `make` or `make stagex` will leverage the steps below
# to check compatibility and build the binary via StageX.

.PHONY: stagex compat build

stagex:	compat build
	@echo "stagex build completed via make."

compat:
	@echo "Beginning Compatibility Check step."
	@./compat.sh
	@echo "  [PASS]  Compatibility Check passed."

build:
	@echo "Entering Build step."
	@./build.sh
	@echo "Build step complete."
