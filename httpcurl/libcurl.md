### Download latest libcurl 

```sh
wget https://curl.se/download/curl-7.86.0.tar.gz
```

### Configure and build libcurl

```sh
./configure --prefix=/home/kxie/open-quantum-safe/oqs-bouncycastle/httpcurl/curl-install --with-openssl=/home/kxie/open-quantum-safe/openssl-install/openssl
make
make install
```

### Use p521_kyber1024 in libcurl
```c
    curl_easy_setopt(curl_handle, CURLOPT_SSL_EC_CURVES, "p521_kyber1024");
```

### Build httpcurl
```sh
make
```

### Run spring-boot http server
```sh
git clone https://github.com/kaiduanx/springboot-tls.git
mvn clean package 
./run.sh
```

### Run httpcurl client
```sh
export LD_LIBRARY_PATH=/home/kxie/open-quantum-safe/openssl-install/openssl/lib/:/home/kxie/qs-bouncycastle/httpcurl/curl-install/lib
kxie@kxie-ubuntu-20:~/open-quantum-safe/httpcurl$./httpcurl.exe 
JSON:{"name": "Erlang","job": "Programmer"}
HTTP RESPONSE CODE:200
Content size is:56, size:56
Hello world OpenQKDNetwork BouncyCastle Spring boot!!!!
```
