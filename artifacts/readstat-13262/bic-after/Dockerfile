FROM regression-unit-framework/base

RUN apt-get update && apt-get install -y make wget

RUN git clone https://github.com/WizardMac/ReadStat readstat && cd readstat && \
    git checkout 1de4f389a8ffb07775cb1d99e33cbfa7e96bccf2
WORKDIR readstat

COPY build.sh $SRC/
COPY fuzz_format_sas7bdat.c $SRC/readstat/src/fuzz/