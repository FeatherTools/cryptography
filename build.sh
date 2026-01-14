#!/usr/bin/env bash

set -eu
set -o pipefail

dotnet tool restore
dotnet tool run paket restore

# shellcheck disable=SC2068
FAKE_DETAILED_ERRORS=true dotnet run --project ./build/build.fsproj -- $@
