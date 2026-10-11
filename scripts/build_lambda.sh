#!/usr/bin/env bash
# Builds the Lambda deployment zip.
#
# Run before `terraform apply`: Terraform reads build/lambda.zip at plan time,
# so the artifact has to exist before the plan, not during it.
#
# python-hcl2 depends on `regex`, which ships a compiled C extension. Wheels
# are therefore resolved for the Lambda runtime's architecture explicitly
# rather than for the build machine's -- installing the host's x86_64 wheel
# into an arm64 function fails at import with a confusing circular-import
# error from the half-loaded extension module.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
STAGE="$BUILD/package"

# Must match `architectures` on aws_lambda_function.scanner.
LAMBDA_ARCH="${LAMBDA_ARCH:-arm64}"
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"

case "$LAMBDA_ARCH" in
  arm64)  PIP_PLATFORM="manylinux2014_aarch64" ;;
  x86_64) PIP_PLATFORM="manylinux2014_x86_64" ;;
  *) echo "unsupported LAMBDA_ARCH: $LAMBDA_ARCH" >&2; exit 1 ;;
esac

rm -rf "$STAGE" "$BUILD/lambda.zip"
mkdir -p "$STAGE"

python3 -m pip install \
  --quiet \
  --target "$STAGE" \
  --platform "$PIP_PLATFORM" \
  --python-version "$PYTHON_VERSION" \
  --implementation cp \
  --only-binary=:all: \
  --requirement "$ROOT/lambda/requirements.txt"

cp "$ROOT"/lambda/*.py "$STAGE/"

# Trim files that only matter at build time. This typically halves the zip,
# which shortens cold starts.
find "$STAGE" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$STAGE" -type d -name "*.dist-info" -prune -exec rm -rf {} +
find "$STAGE" -type d -name "tests" -prune -exec rm -rf {} +

cd "$STAGE"
zip -qr "$BUILD/lambda.zip" .

echo "built build/lambda.zip for $LAMBDA_ARCH ($(du -h "$BUILD/lambda.zip" | cut -f1))"
