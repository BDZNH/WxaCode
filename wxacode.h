#ifndef WXACODE_H
#define WXACODE_H

#include <stdio.h>
#include <string.h>

#include <memory.h>
#include <assert.h>
#include <stdlib.h>

#ifndef __cplusplus
typedef int bool;
#define true 1
#define false 0
#endif

// rapidjson
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

// libcurl(support ssl)
#include <curl/curl.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


    /*存储以POST方式需要发送的数据*/
    struct Request
    {
        char* readptr;
        size_t sizeleft;
    };


    struct Response
    {
        unsigned char* response;
        size_t size;
    };

    /*发送数据的回调函数*/
    static size_t send_callback(char* dest, size_t size, size_t nmemb, void* userp)
    {
        struct Request* wt = (struct Request*)userp;
        size_t buffer_size = size * nmemb;

        if (wt->sizeleft) {
            /* copy as much as possible from the source to the destination */
            size_t copy_this_much = wt->sizeleft;
            if (copy_this_much > buffer_size)
                copy_this_much = buffer_size;
            memcpy(dest, wt->readptr, copy_this_much);

            wt->readptr += copy_this_much;
            wt->sizeleft -= copy_this_much;
            return copy_this_much; /* we copied this many bytes */
        }

        return 0; /* no more data left to deliver */
    }

    /*接收数据的回调函数*/
    static size_t receive_callback(void* data, size_t size, size_t nmemb, void* userp)
    {
        size_t realsize = size * nmemb;
        struct Response* mem = (struct Response*)userp;

        unsigned char* ptr = (unsigned char*)realloc(mem->response, mem->size + realsize + 1);
        if (ptr == NULL)
            return 0;  /* out of memory! */

        mem->response = ptr;
        memcpy(&(mem->response[mem->size]), data, realsize);
        mem->size += realsize;
        mem->response[mem->size] = 0;

        return realsize;
    }

    /*如果定义了 USE_SPECCIFIC_CACERT_PEM ，那么函数第一个参数应该指向一个 catcert.pem 证书*/
#ifdef USE_SPECCIFIC_CACERT_PEM
    int handle_https_callback(const char* certpem, const char* url, bool post, const char* parameter, size_t size_send, void** responsedata, size_t* size_receive, char** content_type, bool verbose)
#else
    int handle_https_callback(const char* url, bool post, const char* parameter, size_t size_send, void** responsedata, size_t* size_receive, char** content_type, bool verbose)
#endif // USE_SPECCIFIC_CACERT_PEM
    {
        assert(url);
        CURL* curl;
        CURLcode res;
        struct Request request;
        struct Response response = { 0 };
        struct curl_slist* headers = NULL;
        int result = 0;

        /*如果parameter非空，那么有数据要发送，就申请相应的发送数据的空间*/
        bool hasParameter = false;
        if (parameter != NULL)
        {
            hasParameter = true;
            size_t len = strlen(parameter);
            size_t min = len < size_send ? len : size_send;
            request.readptr = (char*)parameter;
            request.sizeleft = min;
        }

        res = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_global_init() failed: %s\n", curl_easy_strerror(res));
            return 1;
        }
        curl = curl_easy_init();
        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, url);
            if (post)
            {
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
            }

            /*如果有数据需要发送，就设置相应的数据发送回调函数，要发送的数据和数据长度*/
            if (hasParameter)
            {
                curl_easy_setopt(curl, CURLOPT_READFUNCTION, send_callback);
                curl_easy_setopt(curl, CURLOPT_READDATA, &request);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)request.sizeleft);
            }

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);

            headers = curl_slist_append(headers, "Content-Type: application/json");

            /*如果定义了 USE_SPECCIFIC_CACERT_PEM ，那么设置SSL认证证书*/
#ifdef USE_SPECCIFIC_CACERT_PEM
            curl_easy_setopt(curl, CURLOPT_CAINFO, certpem)
#elif defined(DISABLE_CURL_SSL_VERIFY) // 如果定义了 DISABLE_CURL_SSL_VERIFY 证书认证，那么就设置curl不强制认证服务器
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
#endif // USE_SPECCIFIC_CACERT_PEM


            if (verbose)
            {
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            }

            res = curl_easy_perform(curl);
            if (res == CURLE_OK)
            {
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                if (http_code == 200)
                {
                    /*curl_easy_cleanup(curl) 会释放掉 tmp_content_type*/
                    char* tmp_content_type = NULL;
                    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &tmp_content_type);
                    if (tmp_content_type)
                    {
                        size_t tmplen = strlen(tmp_content_type);
                        *content_type = (char*)malloc(tmplen + 1);
                        memset(*content_type, 0, tmplen + 1);
                        memcpy(*content_type, tmp_content_type, tmplen);
                    }
                    /*用户需要自行释放 responsedata */
                    *responsedata = response.response;
                    *size_receive = response.size;
                }
                else
                {
                    result = -2;
                    fprintf(stderr, "net work error with http code %ld", http_code);
                }
            }
            else
            {
                result = 2;
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            }

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
        return result;
    }



#ifdef __cplusplus
}
#endif // __cplusplus



#ifdef USE_SPECCIFIC_CACERT_PEM
int get_wxacode_access_token(const char* certpem, const char* appid, const char* appsecret, char** access_token, bool verbose)
#else
int get_wxacode_access_token(const char* appid, const char* appsecret, char** access_token, bool verbose)
#endif // USE_SPECCIFIC_CACERT_PEM
{
    assert(appid);
    assert(appsecret);
    const char* wxacode_domain = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=";
    const char* secret_param = "&secret=";
    size_t url_len = strlen(wxacode_domain) + strlen(appid) + strlen(secret_param) + strlen(appsecret);
    char* url = (char*)malloc(url_len + 1);
    if (!url)
    {
        return -1;/*out of mempry*/
    }
    memset(url, 0, url_len + 1);
    sprintf(url, "%s%s%s%s", wxacode_domain, appid, secret_param, appsecret);
    if (verbose)
    {
        printf("access to url:%s\r\n", url);
    }

    char* response = NULL;
    char* content_type = NULL;
    size_t len = 0;
#ifdef USE_SPECCIFIC_CACERT_PEM
    int result = handle_https_callback(certpem, url, false, NULL, 0, (void**)&response, &len, &content_type, verbose);
#else
    int result = handle_https_callback(url, false, NULL, 0, (void**)&response, &len, &content_type, verbose);
#endif // USE_SPECCIFIC_CACERT_PEM
    bool get_access_token = false;
    if (result == 0)
    {
        if (strstr(content_type, "application/json"))
        {
            rapidjson::Document doc;
            doc.Parse(response);
            assert(doc.IsObject());
            if (doc.HasMember("access_token"))
            {
                /*如果返回内容包含 access_token，则提取对应的字段*/
                const char* token = doc["access_token"].GetString();
                size_t token_len = strlen(token);
                *access_token = (char*)malloc(token_len + 1);
                if (*access_token == NULL)
                {
                    return -1;/*out of memory*/;
                }
                memset(*access_token, 0, token_len + 1);
                memcpy(*access_token, token, token_len);
                get_access_token = true;
            }
        }

        if (!get_access_token)
        {
            /*如果返回的 response 不是 json ，就直接将 response 内容传递回去*/
            size_t token_len = strlen(response);
            *access_token = (char*)malloc(token_len + 1);
            if (*access_token == NULL)
            {
                return -1;/*out of memory*/;
            }
            memset(*access_token, 0, token_len + 1);
            memcpy(*access_token, response, token_len);
            result = 4;
        }
    }
    if (url)
    {
        free(url);
        url = NULL;
    }
    if (response)
    {
        free(response);
        response = NULL;
    }
    if (content_type)
    {
        free(content_type);
        content_type = NULL;
    }
    return result;
}

#ifdef USE_SPECCIFIC_CACERT_PEM
int get_wxacode_unlimited(const char* certpem, const char* access_token, unsigned char** qrcode, size_t* size, bool verbose)
#else
int get_wxacode_unlimited(const char* access_token, const char* parameter, unsigned char** qrcode, size_t* size, bool verbose)
#endif // USE_SPECCIFIC_CACERT_PEM
{
    assert(access_token);
    assert(parameter);
    const char* wxacodedomain = "https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=";
    size_t url_len = strlen(wxacodedomain) + strlen(access_token);
    char* url = (char*)malloc(url_len + 1);
    if (url == NULL)
    {
        return -1;/*out of mempry*/
    }
    sprintf(url, "%s%s", wxacodedomain, access_token);
    if (verbose)
    {
        printf("access to url:%s\r\n", url);
    }
    unsigned char* response = NULL;
    char* content_type = NULL;
    size_t len = 0;
#ifdef USE_SPECCIFIC_CACERT_PEM
    int result = handle_https_callback(certpem, url, true, parameter, strlen(parameter), (void**)&response, &len, &content_type, verbose);
#else
    int result = handle_https_callback(url, true, parameter, strlen(parameter), (void**)&response, &len, &content_type, verbose);
#endif // USE_SPECCIFIC_CACERT_PEM

    if (result == 0)
    {
        if (!(strstr(content_type, "image/jpeg")))
        {
            result = 4;
        }
        *qrcode = (unsigned char*)malloc(len + 1);
        if (*qrcode == NULL)
        {
            return -1;/*out of memory*/;
        }
        memset(*qrcode, 0, len + 1);
        memcpy(*qrcode, response, len);
        *size = len;
    }
    return result;
}

#endif // !WXACODE_H
