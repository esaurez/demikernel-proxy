# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#=======================================================================================================================
# Default Paths
#=======================================================================================================================

!ifndef LIB_HOME
LIB_HOME = $(USERPROFILE)
!endif

!ifndef LD_LIBRARY_PATH
LD_LIBRARY_PATH = $(USERPROFILE)/lib
!endif

!ifndef DEMIKERNEL_HOME 
DEMIKERNEL_HOME = $(USERPROFILE)
!endif

!ifndef CONFIG_PATH
CONFIG_PATH = $(DEMIKERNEL_HOME)/config.yaml
!endif

!ifndef PREFIX
PREFIX = $(USERPROFILE)
!endif

!ifndef LD_LIBRARY_PATH
LD_LIBRARY_PATH = $(USERPROFILE)/lib
!endif

#=======================================================================================================================
# Build Configuration
#=======================================================================================================================

BUILD = release
!if "$(DEBUG)" == "yes"
BUILD = dev
!endif

!ifndef MTU
MTU = 1500
!endif

!ifndef MSS
MSS = 1500
!endif

!ifndef X86_64_LXUTIL_DLL_DIR
X86_64_LXUTIL_DLL_DIR = $(USERPROFILE)\Src\hvlite2\.packages\Microsoft.WSL.LxUtil.amd64fre\build\native\bin
!endif

#=======================================================================================================================
# Project Directories
#=======================================================================================================================

SRCDIR = $(MAKEDIR)\src

BUILD_DIR = $(MAKEDIR)\target\release
!if "$(BUILD)" == "dev"
BUILD_DIR = $(MAKEDIR)\target\debug
!endif

#=======================================================================================================================
# Toolchain Configuration
#=======================================================================================================================

!ifndef CARGO
CARGO = $(USERPROFILE)\.cargo\bin\cargo.exe
!endif
CARGO_FLAGS = $(CARGO_FLAGS) --profile $(BUILD)

#=======================================================================================================================
# Build Parameters
#=======================================================================================================================

!ifndef LIBOS
LIBOS = catnap
!endif
CARGO_FEATURES = $(CARGO_FEATURES) --features=$(LIBOS)-libos

# Switch for DPDK
!if "$(LIBOS)" == "catnip"
!ifndef DRIVER
DRIVER = mlx5	# defaults to mlx5, set the DRIVER env var if you want to change this
!endif
CARGO_FEATURES = $(CARGO_FEATURES) --features=$(DRIVER)
!endif

# Enable VM Shared Memory
# Always enabled in windows, as we don't support real shared memory here.
CARGO_FEATURES = $(CARGO_FEATURES) --features=nimble-shmem

!ifndef PROFILER
PROFILE = no
!endif
!if "$(PROFILER)" == "yes"
CARGO_FEATURES = $(CARGO_FEATURES) --features=profiler
!endif


#=======================================================================================================================
# Run Parameters
#=======================================================================================================================

!ifndef LISTEN_ADDR
LISTEN_ADDR = 127.0.0.1
!endif

!ifndef LISTEN_PORT
LISTEN_PORT = 6379
!endif

!ifndef CONNECT_ADDR
CONNECT_ADDR = 127.0.0.1
!endif

!ifndef CONNECT_PORT
CONNECT_PORT = 6380
!endif

ARGS = $(LISTEN_ADDR):$(LISTEN_PORT) $(CONNECT_ADDR):$(CONNECT_PORT)

#=======================================================================================================================

all:
	@echo "LD_LIBRARY_PATH: $(LD_LIBRARY_PATH)"
	@echo "$(CARGO) build $(CARGO_FEATURES) $(CARGO_FLAGS)"
	$(CARGO) build $(CARGO_FEATURES) $(CARGO_FLAGS)

run: all
	$(BUILD_DIR)/demikernel-proxy $(ARGS)

# Builds documentation.
doc:
	$(CARGO) doc $(FLAGS) --no-deps

# Cleans up all build artifacts.
clean:
	del /F target  
	del /F Cargo.lock 
	$(CARGO) clean

# Check code style formatting.
check-fmt:
	$(CARGO) fmt --all -- --check