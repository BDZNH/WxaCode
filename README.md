# WxaCode
WxaCode 是一个根据微信小程序官方文档，使用 libcurl 实现的用于根据自定义参数获取无数量限制，带参数小程序码的 api

## 目录
 - 背景
 - 安装
 - 使用说明
 - 依赖
 - 更新日志

## 背景
微信官方只给出了说明，并不限制语言使用方式，这里使用 C/C++ 实现，给想要使用 C/C++ 来获取小程序码的人一些参考。
微信的文档：
 - [获取小程序码](https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/qr-code.html)
 - [获取无数量限制的小程序码](https://developers.weixin.qq.com/miniprogram/dev/api-backend/open-api/qr-code/wxacode.getUnlimited.html)
 - [接口调用凭证(access_tolen)](https://developers.weixin.qq.com/miniprogram/dev/api-backend/open-api/access-token/auth.getAccessToken.html)

## 安装
WxaCode 是一个 header only 的 api ，只需要将 `wxacode.h` 拷贝至你的工程的 include 目录下即可。

## 使用说明
下面是一个简单的 demo
```C++
#include "wxacode.h"
int main()
{
    char* access_token = NULL;
    const char* appid = "replace your appid here";
    const char* appsecret = "replace your appsecret here";
    int result = get_wxacode_access_token(appid, appsecret, &access_token, true);
    if (result > 0)
    {
        printf("in main func:%s\r\n", access_token);
    }
    else if(result == 0)
    {
        printf("access_token:%s\r\n", access_token);
        unsigned char* qrcode = NULL;
        size_t size = 0;
        const char* parameter = "{\"scene\":\"testtest\"}";
        result = get_wxacode_unlimited(access_token, parameter, &qrcode, &size, true);
        if (result > 0)
        {
            printf("in main func qrcode:%s\r\n", qrcode);
        }
        else if (result == 0)
        {
            FILE* file;
            if (fopen_s(&file, "wxacode.jpg", "wb+") == 0)
            {
                fwrite(qrcode, 1, size, file);
                printf("success write wxacode.jpg\r\n");
            }
            else
            {
                printf("failed to open wxacode.jpg\r\n");
            }
        }
        if (qrcode)
        {
            free(qrcode);
            qrcode = NULL;
        }
    }
    if (access_token)
    {
        free(access_token);
        access_token = NULL;
    }

    return 0;
}
```
## 依赖

`handle_https_callback(...)`使用了 [libcurl](https://curl.se/libcurl/)

`get_wxacode_access_token`和`get_wxacode_unlimited` 使用了 [rapidjson](https://github.com/Tencent/rapidjson)

编译时，需要添加 curl 依赖，也即 `-lcurl`

### 在 Ubuntu 上安装依赖
对于 Ubuntu ，执行以下命令应该可以安装依赖
```bash
sudo apt update
sudo apt install libcurl4-openssl-dev rapidjson-dev
```
### 在 Windows 上安装依赖
在 Windows 上强烈推荐使用 vcpkg 来安装 libcurl ，rapidjson 也是一个仅头文件的库，导入相应的头文件即可。

## FAQ
### 你不想打印很多信息 ?

`get_wxacode_access_token`和`get_wxacode_unlimited`的最后一个参数设置为false即可。

### curl_easy_perform() failed: SSL peer certificate or SSH remote key was not OK
这个是因为 curl 没有找到认证远端服务器的证书，你有两个选择，关闭 curl 的 ssl  验证或者提供证书
 - 关闭 ssl 验证，在导入`wxacode.h`前，定义一个宏`DISABLE_CURL_SSL_VERIFY`即可，像下面这样
```C
//#define DISABLE_CURL_SSL_VERIFY
#include "wxacode.h"
```
 - 提供证书
在导入头文件前定义一个宏 `USE_SPECCIFIC_CACERT_PEM`，此时 `get_wxacode_access_token`和`get_wxacode_unlimited`第一个参数将指向证书文件的，如果你没有可用的证书文件，可以前往[https://curl.se/ca/cacert.pem](https://curl.se/ca/cacert.pem)下载 