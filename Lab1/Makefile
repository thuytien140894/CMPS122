include Makefile.libs

CFLAGS = -Wall
CC = gcc

SRC=$(wildcard *.c)

test: $(SRC)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

check: test
	@./test -single   users4 4 | tee check.out
	@./test -speedy   users4 4 | tee -a check.out
	@./test -multiple users4 4 | tee -a check.out
	@./test -stealthy users4 4 | tee -a check.out

single: test
	@./test -single users4 4
	
multiple: test
	@./test -multiple users4 4
	
speedy: test
	@./test -speedy users4 4
	
stealthy: test
	@./test -stealthy users4 4
	
grade: 
	@if [ -s "check.out" ] ; \
	then \
		./grade.sh ; \
	else \
		make check grade; \
	fi;

clean:
	rm -f passwd test check.out 

submit:
	tar czvf ~/CMPS122-Lab1.tar.gz --exclude=test.c --exclude=crack.h --exclude=users* *.c *.h Makefile.libs
