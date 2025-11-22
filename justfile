# justfile - Task runner for DKIM Verifier
# Usage: just <task>
# Install just: https://github.com/casey/just

# Default task - show available commands
default:
	@just --list

# === Development ===

# Run all checks (lint, typecheck, test, RSR)
verify:
	deno task verify

# Lint code with Deno
lint:
	deno task lint

# Format code with Deno
fmt:
	deno task fmt

# Type check with Deno
check:
	deno task check

# Run tests
test:
	deno task test

# Run tests in watch mode
test-watch:
	deno task test:watch

# Verify RSR compliance
verify-rsr:
	deno task verify-rsr

# === Building ===

# Pack extension into XPI file
pack:
	deno task pack

# Build WebAssembly modules (performance-critical operations)
build-wasm:
	@echo "Building WASM modules..."
	cd wasm/crypto && wasm-pack build --target web
	cd wasm/parser && wasm-pack build --target web
	@echo "WASM modules built successfully"

# === Development Server ===

# Start development server
dev:
	deno task dev

# Load extension in Thunderbird (requires Thunderbird in PATH)
load-tb:
	@echo "Open Thunderbird and load from: $(pwd)"
	thunderbird --purgecaches

# === Maintenance ===

# Update third-party dependencies
update-deps:
	deno task update-thirdparty

# Clean build artifacts
clean:
	rm -rf *.xpi
	rm -rf wasm/*/pkg
	rm -rf wasm/*/target
	rm -rf node_modules
	@echo "Cleaned build artifacts"

# === Security ===

# Run security audit
audit:
	@echo "Checking for security vulnerabilities..."
	deno run --allow-read --allow-net scripts/security-audit.js

# Verify no secrets in code
check-secrets:
	@echo "Checking for hardcoded secrets..."
	@rg -i "password\s*[:=]\s*['\"][^'\"]{8,}" --type js || echo "✓ No password secrets found"
	@rg -i "api[_-]?key\s*[:=]\s*['\"][^'\"]{10,}" --type js || echo "✓ No API key secrets found"
	@rg -i "token\s*[:=]\s*['\"][^'\"]{10,}" --type js || echo "✓ No token secrets found"

# === Documentation ===

# Generate API documentation
docs:
	@echo "Generating documentation..."
	deno doc --html --name="DKIM Verifier" modules/**/*.mjs.js

# Serve documentation
docs-serve:
	@echo "Serving documentation..."
	deno run --allow-net --allow-read npm:http-server ./docs -p 8080

# === Testing ===

# Run unit tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	deno test --coverage=coverage --allow-read --allow-env

# Generate coverage report
coverage-report:
	deno coverage coverage --lcov --output=coverage.lcov

# === Release ===

# Prepare for release (verify + pack)
release: verify pack
	@echo "Release ready! Extension packed."

# Create git tag for release
tag VERSION:
	@echo "Creating release tag v{{VERSION}}"
	git tag -a v{{VERSION}} -m "Release v{{VERSION}}"
	git push origin v{{VERSION}}

# === Utilities ===

# Count lines of code
loc:
	@echo "Lines of code:"
	@find modules -name "*.mjs.js" | xargs wc -l | tail -1
	@echo "Test code:"
	@find test -name "*.mjs.js" | xargs wc -l | tail -1

# Show project statistics
stats:
	@echo "=== DKIM Verifier Statistics ==="
	@echo "Modules:" $(find modules -name "*.mjs.js" | wc -l)
	@echo "Tests:" $(find test -name "*Spec.mjs.js" | wc -l)
	@echo "Languages:" $(find _locales -type d -depth 1 | wc -l)
	@just loc

# Install git hooks
install-hooks:
	@echo "Installing git hooks..."
	cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Git hooks installed"

# === WASM Development ===

# Initialize WASM projects
init-wasm:
	@echo "Initializing WASM projects..."
	mkdir -p wasm/crypto wasm/parser
	cd wasm/crypto && cargo init --lib
	cd wasm/parser && cargo init --lib

# Test WASM modules
test-wasm:
	cd wasm/crypto && cargo test
	cd wasm/parser && cargo test

# Benchmark WASM vs JS performance
benchmark:
	deno run --allow-read scripts/benchmark-wasm.js

# === CI/CD ===

# Run CI checks (same as GitHub Actions)
ci: lint check test verify-rsr
	@echo "✓ All CI checks passed"

# Simulate release build
ci-release: ci pack
	@echo "✓ Release build successful"
