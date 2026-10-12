# smtp: make test

SBCL ?= sbcl

# Resolve systems from this tree and ./ocicl only, so nothing is picked up
# from other projects on the machine.
LISP = $(SBCL) --noinform --non-interactive --eval '(asdf:initialize-source-registry (quote (:source-registry (:directory "$(CURDIR)/") (:tree "$(CURDIR)/ocicl/") :ignore-inherited-configuration)))'

.PHONY: test stress integration integration-run integration-up integration-down

test:
	$(LISP) --eval '(asdf:test-system :smtp)'

# Load, concurrency and fuzz tests (several minutes; STRESS=section,... to pick).
stress:
	$(SBCL) --dynamic-space-size 4096 --noinform --non-interactive --load tools/stress.lisp

# Tests against real servers (Mailpit, Postfix, Stalwart) in Docker. The
# servers are left running for the next run; make integration-down stops them.
COMPOSE = docker compose -f integration/compose.yaml

integration: integration-up integration-run

# The tests alone, against servers that are already running.
integration-run:
	$(LISP) --eval '(asdf:test-system :smtp/integration)'

integration-up:
	$(COMPOSE) up -d --build --wait --quiet-pull

integration-down:
	$(COMPOSE) down
