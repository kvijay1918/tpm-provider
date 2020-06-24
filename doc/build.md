# Build Instructions
This document contains instructions for using `cicd/Dockerfile` for building `tpm-provider`.  The Docker image created by the Dockerfile is referred to as `gta-devel`.

## Windows Instructions
Add instructions for building tss2 on Windows
- Download vs 2019, add clang
- Open <project dir>/tpm2-tss/tpm2-tss.sln in visual studio
- Update solution file to build release/x64 and use clang LLVM/correct wdk
- Build --> .dlls in x64/release subdirectory
- Copy tss2-sys.dll, tss2-mu.dll and tss2-tcti-tbs.dll to the "<project dir>/out" directory (where tpmprovider.test will be compiled)

Install msys (gcc on Windows)
- Install file at the top of https://www.msys2.org/ (msys2-x86_64-20200602.exe)
- Run steps to update msys from website: pacman -Syu, restart msys and then pacman -Su (export http_proxy/https_proxy if things timout)
- In msys2 prompt, install mingw-gcc compiler: pacman -S mingw-w64-x86_64-gcc
- Also install make: pacman -S make

Build go…
- Copy tss2-mu-dll, tss2-sys.dll and tss2-tcti-tbs.dll into tpmprovider/out project directory (will need to make this directory if it doesn't already exist')
    ==> Consider git submodule in tpm-provider directory
- Start a mingw64 prompt by double clicking c:\msys64\mingw64.exe
- Add go to path
- Run 'make' --> file in/out/tpmprovider.test
- Run test --> out/tpmprovider.test (use --help to see options)


## Rationale for 'gta-devel' 

The `tpm-provider` currently targets RHEL8.0 and requires `tpm2-tss` and `tpm2-abrmd` to interface with the host's TPM.  Installing those packages on RHEL 8.0 will result in the following vesions of Tss2...

    tpm2-tss-2.0.0-4.el8.x86_64
    tpm2-abrmd-2.1.1-3.el8.x86_64

Due to the dependency on Tss2, any project that includes `tpm-provider` (ex. `go-trust-agent` and `workload-agent`) will need to be built on a Linux environment with those libraries present (as well as `tpm2-abrmd-devel`).

While developers could build `tpm-provider` on a physical host or vm with the correct versions of Tss2, the documentation in this repository refers to the use Docker and the `gta-devel` image.

# Building tpm-provider on Linux
## Prerequisites
* Docker
* git access to `tpm-provider`

Building, debuging and ci/cd use the `gta-devel` image defined in cicd/Dockerfile.  It currently uses Fedora 29 and includes tools for compiling go, c/c++, makeself, tpm2-tss, tpm2-abrmd, etc. The image also includes the tpm-simulator.

## Compiling tpm-provider
Currently, `tpm-provider` will be statically linked into go applications (ex. `go-trust-agent`) via `go.mod` and does not need to be built independently.  However, the project does include a Makefile that compiles unit tests into `out/tpmprovider.test` (for convenience).  To compile `tpm-provider`....

1. Create a `gta-devel` docker image...
    1. `cd cicd`
    2. `docker build --tag=gta-devel --build-arg http_proxy=<proxy-if-needed> --build-arg https_proxy=<proxy-if-needed> .`
    3. `docker image ls` should show `gta-devel`
2. Start a new instance of the container, mounting the root code directory as `/docker_host` directory in the container...
    1. `docker run -it -v $(pwd):/docker_host gta-devel -p 9443:1443 /bin/bash` (run this command from the root directory of your development environment so that code projects will be available in the container at '/docker_host')
    2. Configure git to access github to resolve dependencies on other ISecL go libraries.
        1. `git config --global http.proxy <proxy>`
        2. `git config --global https.proxy <proxy>`
        3. `git config --global url."ssh://git@github.com".insteadOf https://github.com`
        4. Create ssh keys in ~/.ssh (id_rsa and id_rsa.pub)
    3. `cd /docker_host/tpm-provider`
    4. `make`
    5. `out/tpmprovider-test` executable is compiled.  All unit tests can be invoked by running `out/tmpprovider.test` or individually by running `out/tpmprovider.test -test.run TestName`.

*Note: The `gta-devel` docker contianer can be used in this fashion to build GTA, but cannot be used to run `tpm2-abrmd` because it must run as a service under `systemd`.  See `Unit Testing and TPM Simulator` below for instructions to run `systemd`, `tpm2-abrmd` and the TPM simulator in the `gta-devel` container.*

# Unit Testing and Tpm Simulator
The `gta-devel` docker image also contains the IBM TPM simulator to support debugging and unit tests.  `tpm2-abrmd` has been configured to use the simulator (in the container) by adding the `--tcti=mssim` arguments to the .service file. 

In order to start the `tpm2-abrmd` service, the docker container must be running systemd.  The following instructions describe how to start `gta-devel` with `ssytemd` in order to run unit tests that use the TPM Simulator.

1. Start an container of `gta-devel` that runs systemd: `docker run --rm --privileged -ti -e 'container=docker' -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v $(pwd):/docker_host -p 9443:1443 gta-devel /usr/sbin/init`
2. Use Docker to 'attach' to the container.
3. Run the unit tests by either...

    a. `make` and run `out/tpmprovider.test` or...

    b. Run `go test ./... -tags=test`

## Starting/Stopping the TPM Simulator
The unit tests will start and stop (reset) the TPM simulator on each test.  However, the state of the simulator/abrmd can be problematic.  In those scenarios, you may be required to manually start/stop the simulator.

To start the simulator and tpm2-abrmd run...

    /simulator/src/tpm_server -rm&
    systemctl start tpm2-abrmd

The simulator and service can be reset/stopped by running...

    kill -9 `pgrep tpm_server`
    systemctl stop tpm2-abrmd

See `cicd/start-tpm-simulator.sh` for additional details.
