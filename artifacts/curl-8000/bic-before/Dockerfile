FROM regression-unit-framework/base

RUN git clone https://github.com/curl/curl.git $SRC/curl && cd $SRC/curl && \
    git checkout e6c22368c6e5426ec2b1cb8a3041ebc98d0ad402

RUN git clone https://github.com/curl/curl-fuzzer.git $SRC/curl_fuzzer
RUN cd $SRC/curl_fuzzer && git reset --hard c4ce63bf55674cebdad03f8bb6adb354bfc63609

COPY curl_fuzzer.cc /src/curl_fuzzer
COPY ossfuzz.sh /src/curl_fuzzer
