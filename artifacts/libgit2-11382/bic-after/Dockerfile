FROM regression-unit-framework/base

RUN git clone https://github.com/libgit2/libgit2 libgit2 && cd libgit2 && \
    git checkout 7fafec0

WORKDIR libgit2

COPY build.sh $SRC/