# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#=======================================================================================================================
# Default Paths
#=======================================================================================================================

export LIB_HOME ?= $(HOME)
export PKG_CONFIG_PATH ?= $(shell find $(LIB_HOME)/lib/ -name '*pkgconfig*' -type d 2> /dev/null | xargs | sed -e 's/\s/:/g')
export LD_LIBRARY_PATH ?= $(LIB_HOME)/lib:$(shell find $(LIB_HOME)/lib/ -name '*x86_64-linux-gnu*' -type d 2> /dev/null | xargs | sed -e 's/\s/:/g')
export DEMIKERNEL_HOME ?= $(HOME)
export CONFIG_PATH ?= $(DEMIKERNEL_HOME)/config.yaml

export PREFIX ?= $(HOME)
export PKG_CONFIG_PATH ?= $(shell find $(PREFIX)/lib/ -name '*pkgconfig*' -type d 2> /dev/null | xargs | sed -e 's/\s/:/g')
export LD_LIBRARY_PATH ?= $(HOME)/lib:$(shell find $(PREFIX)/lib/ -name '*x86_64-linux-gnu*' -type d 2> /dev/null | xargs | sed -e 's/\s/:/g')

#=======================================================================================================================
# Build Configuration
#=======================================================================================================================

export BUILD := release
ifeq ($(DEBUG),yes)
export RUST_LOG ?= trace
export BUILD := dev
endif

export MTU ?= 1500
export MSS ?= 1500

#=======================================================================================================================
# Project Directories
#=======================================================================================================================

export SRCDIR = $(CURDIR)/src
export BUILD_DIR := $(CURDIR)/target/release
ifeq ($(BUILD),dev)
export BUILD_DIR := $(CURDIR)/target/debug
endif

#=======================================================================================================================
# Toolchain Configuration
#=======================================================================================================================

# Rust
export CARGO ?= $(shell which cargo || echo "$(HOME)/.cargo/bin/cargo" )
export CARGO_FLAGS += --profile $(BUILD)

#=======================================================================================================================
# Build Parameters
#=======================================================================================================================

export LIBOS ?= catnap
export CARGO_FEATURES := --features=$(LIBOS)-libos

# Switch for DPDK
ifeq ($(LIBOS),catnip)
DRIVER ?= $(shell [ ! -z "`lspci | grep -E "ConnectX-[4,5,6]"`" ] && echo mlx5 || echo mlx4)
CARGO_FEATURES += --features=$(DRIVER)
endif

# Enable VM Shared Memory
export VM_SHM ?= no
ifeq ($(VM_SHM),yes)
CARGO_FEATURES += --features=demikernel/virtio-shmem
CARGO_FEATURES += --features=virtio-shmem
endif

#=======================================================================================================================
# Run Parameters
#=======================================================================================================================

export LISTEN_ADDR ?= 127.0.0.1
export LISTEN_PORT ?= 6379
export CONNECT_ADDR ?= 127.0.0.1
export CONNECT_PORT ?= 6380
export ARGS := $(LISTEN_ADDR):$(LISTEN_PORT) $(CONNECT_ADDR):$(CONNECT_PORT)

#=======================================================================================================================

all:
	@echo "LD_LIBRARY_PATH: $(LD_LIBRARY_PATH)"
	@echo "PKG_CONFIG_PATH: $(PKG_CONFIG_PATH)"
	@echo "$(CARGO) build $(CARGO_FEATURES) $(CARGO_FLAGS)"
	$(CARGO) build $(CARGO_FEATURES) $(CARGO_FLAGS)

run: all
	$(BUILD_DIR)/demikernel-proxy $(ARGS)

# Builds documentation.
doc:
	$(CARGO) doc $(FLAGS) --no-deps

# Cleans up all build artifacts.
clean:
	rm -rf target ; \
	rm -f Cargo.lock ; \
	$(CARGO) clean

# Check code style formatting.
check-fmt:
	$(CARGO) fmt --all -- --check
