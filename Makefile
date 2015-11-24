REBAR = $(shell pwd)/rebar3
ELVIS = $(shell pwd)/elvis

.PHONY: version all tree

all: version compile

include fifo.mk

version:
	@echo "$(shell git symbolic-ref HEAD 2> /dev/null | cut -b 12-)-$(shell git log --pretty=format:'%h, %ad' -1)" > wiggle.version

version_header: version
	@echo "-define(VERSION, <<\"$(shell cat wiggle.version)\">>)." > include/wiggle_version.hrl
