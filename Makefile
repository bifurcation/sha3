CFLAGS = -O3

speed_test: speed_test.o sha3.o sha512.o
	$(CC) -o $@ $^

.PHONY: test
test: speed_test
	./speed_test

sha3: sha3.c
	$(CC) -DTEST -o $@ $^

clean:
	git clean -fX
