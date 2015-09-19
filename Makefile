REBAR = $(shell pwd)/rebar3

.PHONY: version all tree

all: .git/hooks/pre-commit compile

.git/hooks/pre-commit: hooks/pre-commit
	cp hooks/pre-commit .git/hooks

quick-xref:
	$(REBAR) xref

quick-test:
	$(REBAR) eunit

version:
	@echo "$(shell git symbolic-ref HEAD 2> /dev/null | cut -b 12-)-$(shell git log --pretty=format:'%h, %ad' -1)" > wiggle.version

version_header: version
	@echo "-define(VERSION, <<\"$(shell cat wiggle.version)\">>)." > include/wiggle_version.hrl

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean
	[ -d ebin ] && rm -r ebin || true

distclean: clean devclean
	$(REBAR) delete-deps

test: all
	$(REBAR) xref
	$(REBAR) eunit

###
### Docs
###
docs:
	$(REBAR) doc

##
## Developer targets
##

xref: compile
	@$(REBAR) xref

##
## Dialyzer
##
APPS = kernel stdlib sasl erts ssl tools os_mon runtime_tools crypto inets \
	xmerl webtool snmp public_key mnesia eunit syntax_tools compiler
COMBO_PLT = $(HOME)/.wiggle_combo_dialyzer_plt

check_plt: deps compile
	dialyzer --check_plt --plt $(COMBO_PLT) --apps $(APPS) \
		deps/*/ebin ebin

build_plt: deps compile
	dialyzer --build_plt --output_plt $(COMBO_PLT) --apps $(APPS) \
		deps/*/ebin ebin

dialyzer: deps compile
	@echo
	@echo Use "'make check_plt'" to check PLT prior to using this target.
	@echo Use "'make build_plt'" to build PLT prior to using this target.
	@echo
	@sleep 1
	dialyzer -Wno_return --plt $(COMBO_PLT) deps/*/ebin ebin | grep -v -f dialyzer.mittigate


cleanplt:
	@echo
	@echo "Are you sure?  It takes about 1/2 hour to re-build."
	@echo Deleting $(COMBO_PLT) in 5 seconds.
	@echo
	sleep 5
	rm $(COMBO_PLT)

tree:
	rebar3 tree | grep -v '=' | sed 's/ (.*//' > tree

tree-diff: tree
	git diff test -- tree
