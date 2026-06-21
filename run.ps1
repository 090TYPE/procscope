# Build and run procscope in Docker on Windows (Docker Desktop + WSL2 backend).
# Any arguments are forwarded to procscope, e.g. .\run.ps1 -p 1234
$ErrorActionPreference = "Stop"

docker build -t procscope:dev .
docker run --rm -it --privileged --pid=host `
    -v /sys/kernel/btf:/sys/kernel/btf:ro `
    procscope:dev @args
