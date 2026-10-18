# Shared application environment for both outputs below.
# Application: docker build -t sandbox-escape-finder:latest .
# Tests:       docker build --target test -t sandbox-escape-finder:test .
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS app

# Install the package and its real dependency (RestrictedPython) into the image
# so the isolated worker can import them with no network at runtime.
WORKDIR /opt/sandbox_escape_finder
COPY pyproject.toml README.md ./
COPY sandbox_escape_finder ./sandbox_escape_finder
RUN pip install --no-cache-dir .
COPY config ./config
COPY examples ./examples

# Don't try to write .pyc files to the read-only root filesystem at runtime.
ENV PYTHONDONTWRITEBYTECODE=1

# Drop privileges by default (the prober also passes --user nobody).
USER 65534:65534

# Run the corpus and print a report when started from Docker Desktop or with
# `docker run`. The default subprocess backend runs workers inside this Linux
# container; it does not require Docker inside Docker.
# No ENTRYPOINT: DockerIsolation.run() overrides CMD with the internal worker
# command and supplies its JSON request on stdin for each disposable container.
CMD ["python", "-I", "-m", "sandbox_escape_finder.cli", "probe"]

# Test output: add the locked testing tools and the single test directory.
FROM app AS test
USER 0:0
COPY requirements-test-lock.txt ./requirements-test-lock.txt
RUN pip install --no-cache-dir -c requirements-test-lock.txt -e ".[test]"
COPY tests ./tests
USER 65534:65534
# The eight Docker-backend tests are orchestrated from the host separately.
CMD ["python", "-m", "pytest", "-q", "-m", "not docker", "-p", "no:cacheprovider"]

# Keep the application as the default output of a plain `docker build`.
# This inherits app's non-root user and probe command, without testing tools.
FROM app AS runtime
