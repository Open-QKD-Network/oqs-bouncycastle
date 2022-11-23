httpcurl.exe: httpcurl.c
	rm -f httpcurl.exe
	gcc -g -I./curl-install/include -o httpcurl.exe httpcurl.c -l curl -L./curl-install/lib
clean:
	rm -rf httpcurl.exe
