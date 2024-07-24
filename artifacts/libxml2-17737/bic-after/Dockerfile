FROM regression-unit-framework/base

RUN git clone https://gitlab.gnome.org/GNOME/libxml2.git libxml2 && cd libxml2 && \
    git checkout 1fbcf4098ba2aefe241de8d7ceb229b995d8daec

COPY build.sh /src/
COPY *.cc *.h *.dict /src/