#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <curl/curl.h>
#define CURL_ERROR_BUF_LEN 1000

typedef enum http_request_type {
	HTTP_REQUEST_TYPE_GET,
	HTTP_REQUEST_TYPE_POST
} http_request_type_t;

static int make_http_request(char* url, http_request_type_t type, char* body_type, char* body);

struct curl_response {
	char *memory;
	size_t size;
};

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct curl_response *mem = (struct curl_response *)userp;

	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (!ptr) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

static int make_http_request(char* url, http_request_type_t type, char* body_type, char* body) {
	CURL *curl_handle;
	CURLcode curl_res = 0;
	long http_response_code;
	struct curl_slist *header_list = NULL;
	char curl_err_buf[CURL_ERROR_BUF_LEN];
	struct curl_response chunk = {.memory = malloc(0),
					.size = 0};

	if (!url || (strlen(url) < 4 || strncmp(url, "http", 4))) {
		printf("url must not be empty and starts with http:%s\n", url);
		return -1;
	}
	curl_handle = curl_easy_init();
	if (!curl_handle) {
		printf("Failes in curl_easy_init()\n");
		return -1;
	}
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_write_cb);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
	if (strlen(url) > 5 && (!strncmp(url, "https", 5) || !strncmp(url, "HTTPS", 5))) {
		curl_easy_setopt(curl_handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
		// Use hybrid key exchange
		curl_easy_setopt(curl_handle, CURLOPT_SSL_EC_CURVES, "p521_kyber1024");
	} else {
		curl_easy_setopt(curl_handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
	}

	switch (type) {
	case HTTP_REQUEST_TYPE_GET:
		curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);
		break;
	case HTTP_REQUEST_TYPE_POST:
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
		if (body) {
			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, strlen(body));
			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, (void *) body);
		}
		if (body_type) {
			char ct[256] = {0};
			snprintf(ct, 256, "Accept: %s", body_type);
			header_list = curl_slist_append(NULL, ct);
			memset(ct, 0, 256);
			snprintf(ct, 256, "Content-Type: %s", body_type);
			header_list = curl_slist_append(header_list, ct);
		}
		break;
	default:
		break;
	}
	curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 3); // 3 seconds
	curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 3 * 3);
	//curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

	if (header_list) {
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, header_list);
	}

	curl_res = curl_easy_perform(curl_handle);
	if (curl_res != CURLE_OK) {
		snprintf(curl_err_buf, sizeof(curl_err_buf), "Error in CURL: %s", curl_easy_strerror(curl_res));
		printf("Fails to perform curl:%s\n", curl_err_buf);
		if (header_list) {
			curl_slist_free_all(header_list);
		}
		curl_easy_cleanup(curl_handle);
		return -1;
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_response_code);
	printf("HTTP RESPONSE CODE:%ld\n", http_response_code);
	printf("Content size is:%d, size:%d\n%s\n", chunk.size, strlen(chunk.memory), chunk.memory);
	if (header_list) {
		curl_slist_free_all(header_list);
	}
	curl_easy_cleanup(curl_handle);
	free(chunk.memory);
	return 0;
}

int main() {
  //make_http_request("http://www.example.com", HTTP_REQUEST_TYPE_GET, 0, 0);
  char json[1024] = { 0 };
  snprintf(json, 1024, "{\"name\": \"%s\",\"job\": \"Programmer\"}", "Erlang");
  printf("JSON:%s\n", json);
  make_http_request("https://127.0.0.1:8080", HTTP_REQUEST_TYPE_GET, "text/html", json);
  return 1;
}
