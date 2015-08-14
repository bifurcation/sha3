CFLAGS = -O3

speed_test: speed_test.o sha3.o sha512.o
	$(CC) -o speed_test $^

.PHONY: test
test: speed_test
	./speed_test

clean:
	git clean -fX
