# syntax=docker/dockerfile:1
FROM ubuntu:bionic
ARG libc_version=2.27-3ubuntu1.5
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update && \
    apt-get -y install --no-install-recommends --allow-downgrades \
        build-essential \
        curl \
        dbus-x11 \
        dconf-cli \
        dpkg-dev \
        file \
        gdb \
        gdbserver \
        git \
        gnome-terminal \
        libc-dev-bin="$libc_version" \
        libc6="$libc_version" \
        libc6-dbg="$libc_version" \
        libc6-dev="$libc_version" \
        libcanberra-gtk3-module \
        libffi-dev \
        libssl-dev \
        python3 \
        python3-dev \
        python3-pip \
        strace \
        vim \
        wget
RUN cd /usr/src && apt-get source libc6="$libc_version"
RUN apt-get install -y --no-install-recommends --allow-downgrades python3-setuptools
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install \
        pwntools \
        rpyc \
        z3-solver
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

