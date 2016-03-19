REBAR:=rebar

.PHONY: all erl test clean doc hexp

all: erl

erl:
	$(REBAR) get-deps compile

test: all
	@mkdir -p .eunit
	$(REBAR) skip_deps=true eunit

clean:
	$(REBAR) clean
	-rm -rvf deps ebin doc .eunit

hexp:
	MIX_EXS=package.exs mix hex.publish

doc:
	$(REBAR) doc

