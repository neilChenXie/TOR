proxy: proxy.o func.o
	gcc -o proxy -g proxy_2.o func.o
proxy.o: proxy_2.c func.h func.c
	gcc -g -c -Wall proxy_2.c
func.o: func.h func.c 
	gcc -g -c -Wall func.c

clean:
	rm proxy *.o stage*out
