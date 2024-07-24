rm -f libfuzzer.a libfuzzer.o
gclang StandaloneFuzzTargetMain.c -c -fPIC -o driver.o
ar r libfuzzer.a driver.o
