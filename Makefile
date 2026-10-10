# smtp: make test

SBCL ?= sbcl

# Resolve systems from this tree and ./ocicl only, so nothing is picked up
# from other projects on the machine.
LISP = $(SBCL) --noinform --non-interactive --eval '(asdf:initialize-source-registry (quote (:source-registry (:directory "$(CURDIR)/") (:tree "$(CURDIR)/ocicl/") :ignore-inherited-configuration)))'

.PHONY: test

test:
	$(LISP) --eval '(asdf:test-system :smtp)'
