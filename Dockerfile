FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

# The desktop's system packages come from a dated Debian snapshot, so a build
# is reproducible and a later archive update cannot change what it installs.
# (The date is the one the base image above was built against.)
RUN printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/20261005T000000Z\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/20261005T000000Z\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' \
      > /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      xvfb openbox chromium fonts-liberation ca-certificates \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man \
# Chromium runs with --disable-gpu on its bundled SwiftShader, so the system
# Mesa/LLVM stack, ghostscript, and the icon/font extras are dead weight.
# They are only soft needs of chromium's dependency closure; drop them and
# every locale but en-US. (Same RUN as the install: a later layer cannot
# shrink an earlier one.)
 && dpkg --purge --force-depends libgl1-mesa-dri libllvm15 libz3-4 libgs10 \
      libgs-common fonts-urw-base35 adwaita-icon-theme \
 && find /usr/lib/chromium/locales -type f ! -name 'en-US.pak' -delete

RUN useradd --uid 1000 --create-home --home-dir /home/agent --shell /bin/bash agent \
 && mkdir -p /home/agent/workspace /opt/loom-computer /tmp/.X11-unix \
 && chmod 1777 /tmp/.X11-unix \
 && chown -R agent:agent /home/agent

WORKDIR /opt/loom-computer
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY loom_computer ./loom_computer
COPY image ./image

USER 1000:1000
WORKDIR /home/agent/workspace
ENV PYTHONPATH=/opt/loom-computer DISPLAY=:99 HOME=/home/agent

EXPOSE 8787
CMD ["/opt/loom-computer/image/entrypoint.sh"]
