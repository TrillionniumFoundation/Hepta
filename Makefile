# Each invocation constructs a fresh source-bound native result.
.PHONY: all validate source cold check source-bootstrap release
.DEFAULT_GOAL := all

SOURCE ?= $(CURDIR)
BOOTSTRAP ?=
OUTPUT_PREFIX ?=
NATIVE_BUILD ?= hia-cold-build
TOOLCHAIN = $(OUTPUT_PREFIX)-toolchain
COLD_OUTPUT = $(OUTPUT_PREFIX)-cold
SOURCE_BOOTSTRAP = $(OUTPUT_PREFIX)-source-bootstrap
RELEASE_OUTPUT = $(OUTPUT_PREFIX)-release

all: release

validate:
	@test -n "$(BOOTSTRAP)" || { printf '%s\n' 'Set BOOTSTRAP to the absolute directory containing the seven bound initial tools.' >&2; exit 2; }
	@case "$(OUTPUT_PREFIX)" in /*) ;; *) printf '%s\n' 'Set OUTPUT_PREFIX to an absolute, unused output prefix whose parent exists.' >&2; exit 2;; esac

source: validate
	"$(NATIVE_BUILD)" --source "$(SOURCE)" --bootstrap "$(BOOTSTRAP)" --output "$(TOOLCHAIN)"

cold: source
	"$(TOOLCHAIN)/hia-cold" --source "$(SOURCE)" --output "$(COLD_OUTPUT)" --toolchain "$(TOOLCHAIN)" --bundle "$(TOOLCHAIN)/cold-bundle.hiadat"

check: cold

source-bootstrap: cold
	"$(TOOLCHAIN)/hia-source-bootstrap" --source "$(SOURCE)" --cold "$(COLD_OUTPUT)" --bootstrap "$(BOOTSTRAP)" --output "$(SOURCE_BOOTSTRAP)"

release: source-bootstrap
	"$(SOURCE_BOOTSTRAP)/hia-release-build" --output "$(RELEASE_OUTPUT)" --compiler "$(COLD_OUTPUT)/qualification/base/B3.flat" --cold-report "$(COLD_OUTPUT)/final-cold.json" --source "$(SOURCE)"
