![latest 0.7.0](https://img.shields.io/badge/latest-0.7.0-green.svg?style=flat)
![nginx 1.14.1](https://img.shields.io/badge/nginx-1.14-brightgreen.svg) ![License MIT](https://img.shields.io/badge/license-MIT-blue.svg) [![Build Status](https://travis-ci.org/jwilder/nginx-proxy.svg?branch=master)](https://travis-ci.org/jwilder/nginx-proxy) [![](https://img.shields.io/docker/stars/jwilder/nginx-proxy.svg)](https://hub.docker.com/r/jwilder/nginx-proxy 'DockerHub') [![](https://img.shields.io/docker/pulls/jwilder/nginx-proxy.svg)](https://hub.docker.com/r/jwilder/nginx-proxy 'DockerHub')


nginx proxy是一个自动配置的nginx反向代理服务器容器，该容器通过通过[docker-gen][1]自动生成反向代理配置并在窗口启动和停止时重新加载配置。

如果想要了解该容器并决定是否用它，请参考 [Automated Nginx Reverse Proxy for Docker][2]。

### 用法

首先运行反向代理容器:

    $ docker run -d -p 80:80 -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy

然后带环境变量`VIRTUAL_HOST=subdomain.youdomain.com`运行需要反向代理的应用容器

    $ docker run -e VIRTUAL_HOST=foo.bar.com  ...

要代理的容器必须[暴露]（https://docs.docker.com/engine/reference/run/expose incoming ports）要代理的端口，可以使用`Dockerfile`中的`EXPOSE`指令，也可以使用`docker run`或`docker create`中的`--expose`的参数。

把要代理主机的域名foo.bar.com解析到运行nginx proxy的主机，然后请求会路由到环境变量的VIRTUAL_HOST=foo.bar.com指定的窗口。

### 镜像变量

nginx-proxy镜像有两种可用类型。

#### jwilder/nginx-proxy:latest

该镜像使用基于debian:jessie的nginx作为基础镜像。

    $ docker pull jwilder/nginx-proxy:latest

#### jwilder/nginx-proxy:alpine

该镜像基于nginx:alpine镜像。使用此镜像完全支持HTTP/2（包括最新Chrome版本所需的ALPN）。还需要有效的SSL证书（参见下面的"SSL Support using letsencrypt"了解更多信息）。

    $ docker pull jwilder/nginx-proxy:alpine

### Docker Compose

```yaml
version: '2'

services:
  nginx-proxy:
    image: jwilder/nginx-proxy
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/tmp/docker.sock:ro

  whoami:
    image: jwilder/whoami
    environment:
      - VIRTUAL_HOST=whoami.local
```

```shell
$ docker-compose up
$ curl -H "Host: whoami.local" localhost
I'm 5b129ab83266
```

### IPv6支持

通过将环境变量`ENABLE_IPV6`设置为`true`来激活容器的IPv6支持：

    $ docker run -d -p 80:80 -e ENABLE_IPV6=true -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy

### 多端口

如果容器公开多个端口，nginx-proxy将默认为在端口80上运行的服务。如果需要指定不同的端口，可以设置环境变量VIRTUAL_PORT来选择不同的端口。如果容器只暴露一个端口，并且设置了环境变量VIRTUAL_HOST，那么就会使用该端口。

  [1]: https://github.com/jwilder/docker-gen
  [2]: http://jasonwilder.com/blog/2014/03/25/automated-nginx-reverse-proxy-for-docker/

### 多域名

如果一个容器要支持多个域名（虚拟主机），可以用逗号分隔多个域名。例如，`foo.bar.com,baz.bar.com,bar.com`，每个虚拟主机使用相同设置。

### 域名通配符

您还可以在域名的开头和结尾使用通配符，如`*.bar.com` 或 `foo.bar.*`。或者甚至是一个正则表达式，它可以与支持通配符的DNS服务（如[xip.io](http://xip.io)结合使用，使用`~^foo\.bar\..*\.xip\.io`将匹配`foo.bar.127.0.0.1.xip.io`, `foo.bar.10.0.2.2.xip.io`和所有其他给定的ip。有关此主题的详细信息，请参阅nginx文档中关于[`server_names`](http://nginx.org/en/docs/http/server_names.html)。

### 多网络

在Docker 1.9中添加了[overlay networking](https://docs.docker.com/engine/userguide/networking/get-started-overlay/)后，`nginx-proxy`容器可能需要连接到多个网络上的后端容器（应用容器）。默认情况下，如果在创建`nginx-proxy`容器时未设置`--net`参数，则将仅附加到默认的`bridge`网络。这意味着它将无法连接到`bridge`以外的网络上的容器。

如果希望将`nginx-proxy`容器连接到其他网络，则必须在`docker create`或`docker run`命令中设置`--net=my-network`参数。在编写本文时，在容器创建时只能指定单个网络，要附加到其他网络，可以在创建容器后使用`docker network connect`命令：

```console
$ docker run -d -p 80:80 -v /var/run/docker.sock:/tmp/docker.sock:ro \
    --name my-nginx-proxy --net my-network jwilder/nginx-proxy
$ docker network connect my-other-network my-nginx-proxy
```

在本例中，`my-nginx-proxy`容器将连接到`my-network`和`my-other-network`，并且可以反向代理到附加到这些网络上的其他容器。

### Internet VS. 本地网络访问

如果您允许来自公共Internet的流量访问您的`nginx-proxy`容器，您可能希望将某些容器仅限于内部网络，不允许从公共Internet访问它们。在需要限制为内部网络的容器上，应设置环境变量`NETWORK_ACCESS=internal`。默认情况下，*内部*网络定义为`127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16`。要更改被作为内部网络的列表，请把以下内容存为配置文件（可以按需要修改）并挂载到`nginx-proxy` 的`/etc/nginx/network_internal.conf`：

```
# 这些网络作为"内部网络"
allow 127.0.0.0/8;
allow 10.0.0.0/8;
allow 192.168.0.0/16;
allow 172.16.0.0/12;

# 从其他网络过来的流量都将被拒绝
deny all;
```

当启用`仅内部访问`时，将向被拒的外部客户端返回`HTTP 403 Forbidden`错误

>如果在`nginx-proxy`前面有一个隐藏客户端IP的负载均衡器或反向代理（例如：AWS应用程序或弹性负载均衡器），则需要使用nginx `realip`模块（须提前安装）从HTTP请求头中提取客户端IP。有关详细信息，请参阅[nginx realip module configuration](http://nginx.org/en/docs/http/ngx_http_realip_module.html)。这个配置可以添加到一个新的配置文件中，并挂载到在`/etc/nginx/conf.d/`。

### 启用SSL的后端应用窗口

如果需要反向代理服务器使用HTTPS连接到后端应用容器，则在应用容器上设置`VIRTUAL_PROTO=https`环境变量。

>注意：如果使用`VIRTUAL_PROTO=https`，并且应用容器暴露端口80和443，`nginx-proxy`将在端口80上使用https。这几乎肯定不是您想要的，所以您还应该在应用容器中设置环境变量`VIRTUAL_PORT=443`。

### uWSGI应用容器

如果要连接到uWSGI应用，请在应用容器上设置环境变量`VIRTUAL_PROTO=uwsgi`。您的应用容器应该监听一个端口，而不是而不是暴露socket的那个端口。

### FastCGI应用容器
 
如果要连接到FastCGI应用，请在应用容器上设置环境变量`VIRTUAL_PROTO=fastcgi`。您的应用容器应该监听一个端口，而不是而不是暴露socket的那个端口。
If you would like to connect to FastCGI backend, set `VIRTUAL_PROTO=fastcgi` on the
backend container. Your backend container should then listen on a port rather
than a socket and expose that port.
 
### FastCGI文件根目录

如果使用fastcgi，可以设置环境变量`VIRTUAL_ROOT=xxx` 来指定文件根目录


### 默认域名

通过设置环境变量`DEFAULT_HOST=foo.bar.com`来设置nginx的默认域名，例如：

    $ docker run -d -p 80:80 -e DEFAULT_HOST=foo.bar.com -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy


### 独立容器

nginx-proxy也可以使用[jwilder/docker-gen](https://index.docker.io/u/jwilder/docker-gen/)镜像和官方[nginx](https://registry.hub.docker.com/_/nginx/)镜像来作为两个独立的容器运行。 

您可能希望这样做以防止将docker套接字绑定到公开暴露的容器服务。

可以使用docker-compose来演示这种用法:

```console
$ docker-compose --file docker-compose-separate-containers.yml up
$ curl -H "Host: whoami.local" localhost
I'm 5b129ab83266
```

要作为独立容器运行，需要在您主机上有[nginx.tmpl](https://github.com/jwilder/nginx-proxy/blob/master/nginx.tmpl) 文件。

首先带一个volume来启动nginx:

    $ docker run -d -p 80:80 --name nginx -v /tmp/nginx:/etc/nginx/conf.d -t nginx

然后用共享卷和模板启动docker-gen容器:

```
$ docker run --volumes-from nginx \
    -v /var/run/docker.sock:/tmp/docker.sock:ro \
    -v $(pwd):/etc/docker-gen/templates \
    -t jwilder/docker-gen -notify-sighup nginx -watch /etc/docker-gen/templates/nginx.tmpl /etc/nginx/conf.d/default.conf
```

最后，带环境变量`VIRTUAL_HOST`启动应用容器。

    $ docker run -e VIRTUAL_HOST=foo.bar.com  ...
	
### 使用letsencrypt来启用SSL支持

[letsencrypt-nginx-proxy-companion](https://github.com/JrCs/docker-letsencrypt-nginx-proxy-companion)是一个轻量级的ginx-proxy配套容器。它允许创建/更新Let's Encrypt SSL证书。

将环境变量`DHPARAM_GENERATION`设置为`false`来完全禁用Diffie-Hellman参数。这还将忽略`nginx-proxy`自动生成的配置。
默认值为`true`

     $ docker run -e DHPARAM_GENERATION=false ....
	 
### SSL 支持

使用单域名，通配符和SNI证书支持SSL，使用证书的命名约定或可选地将证书名称（对于SNI）指定为环境变量。

启用SSL:

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/certs:/etc/nginx/certs -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy

`/path/to/certs`目录中应包含正在使用的任何虚拟主机的证书和私钥。证书和密钥应以虚拟主机为文件名并使用.crt和.key扩展名。例如，具有`VIRTUAL_HOST=foo.bar.com`的容器应该在certs目录中包含`foo.bar.com.crt` 和 `foo.bar.com.key`文件。

如果您在虚拟化环境（Hyper-V，VirtualBox等）中运行容器，则/path/to/certs必须存在于虚拟机中或可被虚拟机访问的宿主机目录。默认情况下，Docker无法物理机的目录装载到虚拟机中运行的容器。

#### Diffie-Hellman Groups

Diffie-Hellman组默认是启用的，并在`/etc/nginx/dhparam/dhparam.pem`中使用预生成的密钥。您可以在该位置挂载其他的`dhparam.pem`文件来覆盖默认证书。
要为每个虚拟主机使用自定义的`dhparam.pem` 文件，文件应以虚拟主机域名为文件名且具有`dhparam`后缀和`.pem`。例如，具有`VIRTUAL_HOST=foo.bar.com`的容器应在`/etc/nginx/certs`目录中包含一个`foo.bar.com.dhparam.pem`文件。

> 注意: 如果没有挂载自定义的`dhparam.pem`文件, 则在启动时会自动生成一个。由于生成新的`dhparam.pem`可能需要几分钟，因此它在后台以低优先级完成。生成完成后，`dhparam.pem`将保存在持久卷上，并重新加载nginx。此生成过程仅在您第一次启动nginx-proxy时发生。

> 兼容性警告：对于A级安全性，默认生成的`dhparam.pem`密钥为2048位。一些较旧的客户端（如Java 6和7）不支持超过1024位的DH密钥。为了支持这些客户端，您必须提供自己的`dhparam.pem`，或者通过传递`-e DHPARAM_BITS=1024`告诉nginx-proxy在启动时生成1024位密钥。

在独立容器设置中，没有预生成的密钥可用，并且[jwilder/docker-gen](https://index.docker.io/u/jwilder/docker-gen/)镜像和官方[nginx](https://registry.hub.docker.com/_/nginx/)图像都不会生成一个。如果您仍然希望在独立容器设置中使用A+级安全性，则必须手动生成2048位DH密钥文件并将其挂载在nginx容器的`/etc/nginx/dhparam/dhparam.pem`目录。


#### 通配符证书

通配符证书和密钥应以域名命名，扩展名为`.crt`和`.key`。例如，`VIRTUAL_HOST=foo.bar.com`将使用证书名称`bar.com.crt`和`bar.com.key`。


#### SNI

如果您的证书支持多域名，则可以使用参数`CERT_NAME=<name>`启动容器以指明要使用的证书。例如，`*.foo.com`和 `*.bar.com`的证书可以命名为`shared.crt`和`shared.key`。使用参数`VIRTUAL_HOST=foo.bar.com`和`CERT_NAME=shared`运行的容器将使用此共享证书。


#### OCSP装订

OCSP装订（英语：OCSP Stapling），正式名称为TLS证书状态查询扩展，可代替在线证书状态协议（OCSP）来查询X.509证书的状态。服务器在TLS握手时发送事先缓存的OCSP响应，用户只需验证该响应的有效性而不用再向数字证书认证机构（CA）发送请求。
要为域启用OCSP Stapling，`nginx-proxy`将在`/etc/nginx/certs/<domain>.chain.pem`中查找包含可信CA证书链的PEM证书，`VIRTUAL_HOST`指令中的`<domain>`是域名。 。此文件的格式是公共PEM CA证书的串联，从最靠近SSL证书的中间CA开始，一直到根CA。这通常被称为“SSL证书链”。如果找到，则将此文件名传递给NGINX [`ssl_trusted_certificate` directive](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_trusted_certificate)并启用OCSP Stapling。


#### SSL支持是如何工作的

默认的SSL密码配置基于[Mozilla intermediate profile](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29)，该配置文件应提供与Firefox 1, Chrome 1, IE 7, Opera 5, Safari 1,
Windows XP IE8, Android 2.3, Java 7的客户端兼容性。请注意，为了安全起见，删除了基于DES的TLS密码。该配置还支持HSTS，PFS，OCSP装订和SSL会话缓存。目前支持TLS 1.0,1.1和1.2。 TLS 1.0已被弃用，但它的使用寿命截止日期为2018年6月30日。由于浏览器 Chrome <22，Firefox <27，IE <11，Safari <7，iOS <5，Android 浏览器<5 还依赖TLS 1.0，所以TLS 1.0还包含在内。

如果您不需要向后兼容性，则可以通过设置参数`SSL_POLICY=Mozilla-Modern`使用[Mozilla modern profile](https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility)配置文件。此配置文件支持Firefox 27, Chrome 30, Windows 7中的IE 11,
Edge, Opera 17, Safari 9, Android 5.0, 和Java 8。

通过环境变量`SSL_POLICY`提供的其他策略是[`Mozilla-Old`](https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility)和[AWS ELB Security Policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html)`AWS-TLS-1-2-2017-01`, `AWS-TLS-1-1-2017-01`, `AWS-2016-08`, `AWS-2015-05`, `AWS-2015-03`和`AWS-2015-02`。

请注意，`Mozilla-Old`策略应使用1024位DH密钥以实现兼容性，但此容器生成2048位密钥。 [Diffie-Hellman Groups](#diffie-hellman-groups) 节详细介绍了绕过此方法的不同方法，无论是全局还是每个虚拟主机。 

暴露端口80和443时代理的默认行为如下：

* 如果容器具有可用的证书，则端口80将重定向到该容器的443，以便在可用时始终首选HTTPS。

* 如果容器没有可用的证书，则返回503。

请注意，在后一种情况下，浏览器可能会收到连接错误，因为没有可用于建立连接的证书。名为`default.crt` 和`default.key`的自签名或通用证书将允许客户端浏览器建立SSL连接（可能带有警告），然后接收500错误。

要在SSL和非SSL模式下提供流量而不重定向到SSL，您可以包括环境变量`HTTPS_METHOD=noredirect`（默认为`HTTPS_METHOD=redirect`）。您还可以使用`HTTPS_METHOD=nohttp`完全禁用非SSL站点，或使用`HTTPS_METHOD=nohttps`禁用HTTPS站点。必须在要覆盖默认行为的每个容器上指定`HTTPS_METHOD`。如果使用了`HTTPS_METHOD=noredirect`，则禁用严格传输安全性（HSTS）以防止HTTPS用户被客户端重定向。如果在更改此设置后无法访问HTTP站点，则浏览器可能已缓存HSTS策略并自动将您重定向回HTTPS。您需要清除浏览器的HSTS缓存或使用隐身窗口或另开其他浏览器。

对于HTTPS站点，默认启用[HTTP Strict Transport Security (HSTS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) 且`max-age=31536000`。您可以使用环境变量`HSTS=off`禁用HSTS，或使用诸如`HSTS=max-age=31536000; includeSubDomains; preload`的自定义HSTS配置。 
*WARNING*：HSTS将强制您的用户访问您网站的HTTPS版本达到最长时间 - 即使他们手动输入`http://`。收到HSTS响应后进入HTTP站点的唯一方法是清除浏览器的HSTS缓存。


### 基本认证支持

为了能够保护您的虚拟主机，您必须在目录/etc/nginx/htpasswd/$VIRTUAL_HOST上创建一个名称为`VIRTUAL_HOST`变量值的文件。

```
$ docker run -d -p 80:80 -p 443:443 \
    -v /path/to/htpasswd:/etc/nginx/htpasswd \
    -v /path/to/certs:/etc/nginx/certs \
    -v /var/run/docker.sock:/tmp/docker.sock:ro \
    jwilder/nginx-proxy
```

您如果计划要创建建htpasswd文件，则需要主机上有apache2-utils。请遵循[instructions](http://httpd.apache.org/docs/2.2/programs/htpasswd.html)


### 自定义Nginx配置

如果使用环境变量不满足您定制nginx的需求，您可以在代理范围或每个`VIRTUAL_HOST`基础上提供自定义配置文件。


#### 替换默认代理设置

如果要替换nginx容器的默认代理设置，请在`/etc/nginx/proxy.conf`中添加配置文件。一个具有默认设置的文件如下所示：


```Nginx
# HTTP 1.1 support
proxy_http_version 1.1;
proxy_buffering off;
proxy_set_header Host $http_host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $proxy_connection;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $proxy_x_forwarded_proto;
proxy_set_header X-Forwarded-Ssl $proxy_x_forwarded_ssl;
proxy_set_header X-Forwarded-Port $proxy_x_forwarded_port;

# Mitigate httpoxy attack (see README for details)
proxy_set_header Proxy "";
```

***注意***：如果您提供此文件，它将替换默认值；您可能需要检查.tmpl文件以确保已经包含了所有必需的选项。 

***注意***：默认配置阻止将`Proxy`HTTP请求头发送到下游服务器。这可以防止攻击者使用所谓的[httpoxy attack](http://httpoxy.org)。客户端没有合理的理由发送此标头，并且有许多易受攻击的语言或平台(`CVE-2016-5385`, `CVE-2016-5386`, `CVE-2016-5387`, `CVE-2016-5388`, `CVE-2016-1000109`, `CVE-2016-1000110`, `CERT-VU#797896`)。

#### 代理范围

要在代理范围内添加设置，请在`/etc/nginx/conf.d`下添加以以`.conf`结尾的配置文件。 

这可以在派生镜像中通过在`RUN`命令中创建文件或将文件`COPY`到conf.d`中：

```Dockerfile
FROM jwilder/nginx-proxy
RUN { \
      echo 'server_tokens off;'; \
      echo 'client_max_body_size 100m;'; \
    } > /etc/nginx/conf.d/my_proxy.conf
```

或者可以通过在`docker run`命令中挂载自定义配置来完成：

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/my_proxy.conf:/etc/nginx/conf.d/my_proxy.conf:ro -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy

#### Per-VIRTUAL_HOST

要在每个`VIRTUAL_HOST`添加设置，请在`/etc/nginx/vhost.d`下添加配置文件。与代理范围的情况不同，后者允许多个以`.conf`结尾的配置文件，每个`VIRTUAL_HOST`文件必须在`VIRTUAL_HOST`之后完全命名。

为了允许动态添加和删除后端配置应用虚拟主机，最好将目录`/etc/nginx/vhost.d`映射到宿主机目录，而不是使用派生镜像或挂载单个配置文件。

例如，如果您有一个名为`app.example.com`的虚拟主机，则可以为该主机提供自定义配置，如下所示：

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/vhost.d:/etc/nginx/vhost.d:ro -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy
    $ { echo 'server_tokens off;'; echo 'client_max_body_size 100m;'; } > /path/to/vhost.d/app.example.com

如果您对单个容器使用多个主机名（例如`VIRTUAL_HOST=example.com,www.example.com`），则每个主机名必须存在对应的虚拟主机配置文件。如果要对多个虚拟主机名使用相同的配置，可以使用文件符号链接：

    $ { echo 'server_tokens off;'; echo 'client_max_body_size 100m;'; } > /path/to/vhost.d/www.example.com
    $ ln -s /path/to/vhost.d/www.example.com /path/to/vhost.d/example.com

#### Per-VIRTUAL_HOST默认配置

如果您希望大多数虚拟主机使用默认单个配置，然后覆盖几个特定配置，请将这些设置添加到`/etc/nginx/vhost.d/default`文件中。此文件将用于任何没有与之关联的 `/etc/nginx/vhost.d/{VIRTUAL_HOST}`文件的虚拟主机。

#### Per-VIRTUAL_HOST位置配置

要在每个`VIRTUAL_HOST`基础上将设置添加到"location"块，请在`/etc/nginx/vhost.d`下添加配置文件，就像上一节一样，但后缀为`_location`。 

例如，如果您有一个名为`app.example.com`的虚拟主机，并且您已在另一个自定义文件中配置了proxy_cache`my-cache`，则可以如下方式使用代理缓存：

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/vhost.d:/etc/nginx/vhost.d:ro -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy
    $ { echo 'proxy_cache my-cache;'; echo 'proxy_cache_valid  200 302  60m;'; echo 'proxy_cache_valid  404 1m;' } > /path/to/vhost.d/app.example.com_location

如果您对单个容器使用多个主机名（例如`VIRTUAL_HOST=example.com,www.example.com`），则每个主机名必须存在虚拟主机配置文件。如果要对多个虚拟主机名使用相同的配置，可以使用符号链接：

    $ { echo 'proxy_cache my-cache;'; echo 'proxy_cache_valid  200 302  60m;'; echo 'proxy_cache_valid  404 1m;' } > /path/to/vhost.d/app.example.com_location
    $ ln -s /path/to/vhost.d/www.example.com /path/to/vhost.d/example.com

#### Per-VIRTUAL_HOST位置默认配置

如果您希望大多数虚拟主机使用默认的单个`location` 块配置，然后覆盖几个特定的​​位置，请将这些设置添加到`/etc/nginx/vhost.d/default_location`文件中。此文件将用于任何没有与之关联的`/etc/nginx/vhost.d/{VIRTUAL_HOST}_location`文件的虚拟主机。

### 贡献

在提交拉取请求或issues之前，请检查github以确保issues或拉取请求尚未打开。

#### 在本地运行测试

要运行测试，您需要编译要测试的标签为`jwilder/nginx-proxy:test`的docker镜像：

    docker build -t jwilder/nginx-proxy:test .  # build the Debian variant image

然后启用 [test/pytest.sh](test/pytest.sh) 脚本.

要编译Alpine变体镜像：

    docker build -f Dockerfile.alpine -t jwilder/nginx-proxy:test .  # build the Alpline variant image

然后调用[test/pytest.sh](test/pytest.sh)脚本.


如果你的系统有`make`，则可以调用:

    make test

来自动化测试。
您可以在[test/README.md](test/README.md)文件中了解有关测试套件如何工作以及如何编写新测试的更多信息。

### 需要帮助?

如果您对如何使用镜像有疑问，请在[Q&A Group](https://groups.google.com/forum/#!forum/nginx-proxy)提问
