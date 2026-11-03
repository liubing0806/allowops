# Local test environment for the Arthas stage-0 measurements (see docs/arthas-stage0-report.md).
#   make up      build everything and start jdk8, jdk11, jdk17, jdk21 (127.0.0.1 only)
#   make down    stop and remove all services, including the optional profiles
#   make up-all  start every service and variant
#   make bench   latency matrix of item 5 (about 3 hours, needs JA_OUT=<raw data dir> and an otherwise idle cpuset 4-9)
#   make real-test  run the jvm_arthas builtin against the running jdk8, jdk11, jdk17 and jdk21 services (root through sudo;
#                   set JA_EVIDENCE=<directory> to keep the output of every call)
#   make accept  the stage-2 acceptance measurements of docs/arthas-stage2-acceptance-report.md (about 4.5 hours, needs
#                JA_OUT=<raw data dir> and an otherwise idle cpuset 4-9; images and containers of their own, see compose.accept.yaml)
SHELL := /bin/sh
ROOT := $(CURDIR)
REPO := $(abspath $(ROOT)/../..)
PROFILES := --profile jre --profile variants
SERVICES := jdk8 jdk11 jdk17 jdk21 jre8 jre17 jlink17 noattach8 noattach17 rofs8 rofs17 rofsnotmp17 nohome8 nohome17 root8 root17 xrs8 xrs17 pid1-17 probe8 probe17

ACCEPT_ENV := COMPOSE_FILE=compose.yaml:compose.accept.yaml COMPOSE_PROJECT_NAME=$(or $(COMPOSE_PROJECT_NAME),jvm-arthas-accept) JA_PORT_PREFIX=$(or $(JA_PORT_PREFIX),26)

.PHONY: app probe arthas tools prepare build up up-all down ps bench real-test accept accept-down

app:
	cd app && mvn -q -s $(ROOT)/app/settings.xml -Dmaven.repo.local=$(ROOT)/run/m2 clean package -DskipTests

probe:
	mkdir -p probe/build
	javac --release 8 -d probe/build probe/src/jvmprobe/Probe.java
	jar cfm probe/probe.jar probe/MANIFEST.MF -C probe/build .
	rm -rf probe/build

arthas:
	scripts/fetch-arthas.sh

tools:
	mkdir -p bin
	cd tools && go build -o $(ROOT)/bin/ja-attach ./attach && go build -o $(ROOT)/bin/ja-loadgen ./loadgen
	cd $(REPO) && go build -o $(ROOT)/bin/ja-call ./test/jvm-arthas/acceptcall

prepare:
	for s in $(SERVICES); do mkdir -p run/$$s/logs; chmod 0777 run/$$s/logs; done

build: app probe arthas prepare
	docker compose $(PROFILES) build

up: build prepare
	docker compose up -d

up-all: build prepare
	docker compose $(PROFILES) up -d

down:
	docker compose $(PROFILES) down -v --remove-orphans

ps:
	docker compose $(PROFILES) ps

bench: tools
	for set in main17 jdk8 jdk11 jdk21; do scripts/run_bench.sh $$set || exit 1; done
	python3 scripts/analyze.py $(JA_OUT)/bench --md > $(JA_OUT)/bench/summary.md

real-test:
	mkdir -p bin
	cd $(REPO) && go test -c -o $(ROOT)/bin/real.test ./test/jvm-arthas/real
	cd real && sudo -n env ALLOWOPS_REAL_ARTHAS=1 COMPOSE_PROJECT_NAME=$(COMPOSE_PROJECT_NAME) JA_PORT_PREFIX=$(JA_PORT_PREFIX) JA_EVIDENCE=$(JA_EVIDENCE) $(ROOT)/bin/real.test -test.v -test.timeout 90m

accept: app probe arthas prepare tools
	$(ACCEPT_ENV) docker compose build jdk8 jdk11 jdk17 jdk21
	$(ACCEPT_ENV) scripts/run_accept.sh

accept-down:
	$(ACCEPT_ENV) docker compose $(PROFILES) down -v --remove-orphans
