FROM regression-unit-framework/base

RUN git clone https://github.com/h2o/picotls picotls && cd picotls && \
    git checkout 047cccf

WORKDIR $SRC/picotls

RUN git submodule init
RUN git submodule update

COPY build.sh $SRC/
COPY CMakeLists.txt $SRC/picotls/