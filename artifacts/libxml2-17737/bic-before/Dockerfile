FROM regression-unit-framework/base

RUN git clone https://gitlab.gnome.org/GNOME/libxml2.git libxml2 && cd libxml2 && \
    git checkout 0762c9b69ba01628f72eada1c64ff3d361fb5716

COPY build.sh /src/
COPY *.cc *.h *.dict /src/