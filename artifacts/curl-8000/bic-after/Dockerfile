FROM regression-unit-framework/base

RUN git clone https://github.com/curl/curl.git $SRC/curl && cd $SRC/curl && \
    git checkout dd7521bcc1b7a6fcb53c31f9bd1192fcc884bd56

RUN git clone https://github.com/curl/curl-fuzzer.git $SRC/curl_fuzzer && cd $SRC/curl_fuzzer \
    && git reset --hard c4ce63bf55674cebdad03f8bb6adb354bfc63609

COPY curl_fuzzer.cc ossfuzz.sh /src/curl_fuzzer/
COPY build.sh /src/