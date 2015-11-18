REBAR = $(shell pwd)/rebar3
ELVIS = $(shell pwd)/elvis

.PHONY: version all tree

all: .git/hooks/pre-commit compile

.git/hooks/pre-commit: hooks/pre-commit
	cp hooks/pre-commit .git/hooks

pre-commit: lint xref dialyzer test

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

test:
	$(REBAR) eunit

###
### Docs
###
docs:
	$(REBAR) doc

##
## Developer targets
##

xref:
	$(REBAR) xref

lint:
	$(ELVIS) rock

install-tools:
	cp `which rebar3` `which elvis` .

##
## Dialyzer
##
dialyzer: 
	$(REBAR) dialyzer
	

tree:
	rebar3 tree | grep -v '=' | sed 's/ (.*//' > tree


