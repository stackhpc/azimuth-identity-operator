FROM python:3.9

# Create the user that will be used to run the app
ENV APP_UID 1001
ENV APP_GID 1001
ENV APP_USER app
ENV APP_GROUP app
RUN groupadd --gid $APP_GID $APP_GROUP && \
    useradd \
      --no-create-home \
      --no-user-group \
      --gid $APP_GID \
      --shell /sbin/nologin \
      --uid $APP_UID \
      $APP_USER

# Install tini, which we will use to marshal the processes
RUN apt-get update && \
    apt-get install -y tini && \
    rm -rf /var/lib/apt/lists/*

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED 1

# The operator calls out to the Helm CLI, so install that
ENV HELM_CACHE_HOME /tmp/helm/cache
ENV HELM_CONFIG_HOME /tmp/helm/config
ENV HELM_DATA_HOME /tmp/helm/data
ARG HELM_VERSION=v3.10.2
RUN set -ex; \
    OS_ARCH="$(uname -m)"; \
    case "$OS_ARCH" in \
        x86_64) helm_arch=amd64 ;; \
        aarch64) helm_arch=arm64 ;; \
        *) false ;; \
    esac; \
    curl -fsSL https://get.helm.sh/helm-${HELM_VERSION}-linux-${helm_arch}.tar.gz | \
      tar -xz --strip-components 1 -C /usr/bin linux-${helm_arch}/helm; \
    helm version

# Install dependencies
# Doing this separately by copying only the requirements file enables better use of the build cache
COPY ./requirements.txt /application/
RUN pip install --no-deps --requirement /application/requirements.txt

# Install the application
COPY . /application
RUN pip install --no-deps -e /application

# By default, run the operator using kopf
USER $APP_UID
ENTRYPOINT ["tini", "-g", "--"]
CMD ["kopf", "run", "--module", "azimuth_identity.operator", "--all-namespaces"]
