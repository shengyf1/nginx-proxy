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

nginx-proxy还可以 can also be run as two separate containers using the [jwilder/docker-gen](https://index.docker.io/u/jwilder/docker-gen/)
image and the official [nginx](https://registry.hub.docker.com/_/nginx/) image.

nginx-proxy can also be run as two separate containers using the [jwilder/docker-gen](https://index.docker.io/u/jwilder/docker-gen/)
image and the official [nginx](https://registry.hub.docker.com/_/nginx/) image.

You may want to do this to prevent having the docker socket bound to a publicly exposed container service.

可以使用docker-compose来演示这种用法:

```console
$ docker-compose --file docker-compose-separate-containers.yml up
$ curl -H "Host: whoami.local" localhost
I'm 5b129ab83266
```

To run nginx proxy as a separate container you'll need to have [nginx.tmpl](https://github.com/jwilder/nginx-proxy/blob/master/nginx.tmpl) on your host system.

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

The contents of `/path/to/certs` should contain the certificates and private keys for any virtual
hosts in use.  The certificate and keys should be named after the virtual host with a `.crt` and
`.key` extension.  For example, a container with `VIRTUAL_HOST=foo.bar.com` should have a
`foo.bar.com.crt` and `foo.bar.com.key` file in the certs directory.

If you are running the container in a virtualized environment (Hyper-V, VirtualBox, etc...),
/path/to/certs must exist in that environment or be made accessible to that environment.
By default, Docker is not able to mount directories on the host machine to containers running in a virtual machine.

#### Diffie-Hellman Groups

Diffie-Hellman groups are enabled by default, with a pregenerated key in `/etc/nginx/dhparam/dhparam.pem`.
You can mount a different `dhparam.pem` file at that location to override the default cert.
To use custom `dhparam.pem` files per-virtual-host, the files should be named after the virtual host with a
`dhparam` suffix and `.pem` extension. For example, a container with `VIRTUAL_HOST=foo.bar.com`
should have a `foo.bar.com.dhparam.pem` file in the `/etc/nginx/certs` directory.

> NOTE: If you don't mount a `dhparam.pem` file at `/etc/nginx/dhparam/dhparam.pem`, one will be generated
at startup.  Since it can take minutes to generate a new `dhparam.pem`, it is done at low priority in the
background.  Once generation is complete, the `dhparam.pem` is saved on a persistent volume and nginx
is reloaded.  This generation process only occurs the first time you start `nginx-proxy`.

> COMPATIBILITY WARNING: The default generated `dhparam.pem` key is 2048 bits for A+ security.  Some
> older clients (like Java 6 and 7) do not support DH keys with over 1024 bits.  In order to support these
> clients, you must either provide your own `dhparam.pem`, or tell `nginx-proxy` to generate a 1024-bit
> key on startup by passing `-e DHPARAM_BITS=1024`.

In the separate container setup, no pregenerated key will be available and neither the
[jwilder/docker-gen](https://index.docker.io/u/jwilder/docker-gen/) image nor the offical
[nginx](https://registry.hub.docker.com/_/nginx/) image will generate one. If you still want A+ security
in a separate container setup, you'll have to generate a 2048 bits DH key file manually and mount it on the
nginx container, at `/etc/nginx/dhparam/dhparam.pem`.

#### Wildcard Certificates

Wildcard certificates and keys should be named after the domain name with a `.crt` and `.key` extension.
For example `VIRTUAL_HOST=foo.bar.com` would use cert name `bar.com.crt` and `bar.com.key`.

#### SNI

If your certificate(s) supports multiple domain names, you can start a container with `CERT_NAME=<name>`
to identify the certificate to be used.  For example, a certificate for `*.foo.com` and `*.bar.com`
could be named `shared.crt` and `shared.key`.  A container running with `VIRTUAL_HOST=foo.bar.com`
and `CERT_NAME=shared` will then use this shared cert.

#### OCSP Stapling
To enable OCSP Stapling for a domain, `nginx-proxy` looks for a PEM certificate containing the trusted
CA certificate chain at `/etc/nginx/certs/<domain>.chain.pem`, where `<domain>` is the domain name in
the `VIRTUAL_HOST` directive.  The format of this file is a concatenation of the public PEM CA
certificates starting with the intermediate CA most near the SSL certificate, down to the root CA.  This is
often referred to as the "SSL Certificate Chain".  If found, this filename is passed to the NGINX
[`ssl_trusted_certificate` directive](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_trusted_certificate)
and OCSP Stapling is enabled.

#### How SSL Support Works

The default SSL cipher configuration is based on the [Mozilla intermediate profile](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29) which
should provide compatibility with clients back to Firefox 1, Chrome 1, IE 7, Opera 5, Safari 1,
Windows XP IE8, Android 2.3, Java 7.  Note that the DES-based TLS ciphers were removed for security.
The configuration also enables HSTS, PFS, OCSP stapling and SSL session caches.  Currently TLS 1.0, 1.1 and 1.2
are supported.  TLS 1.0 is deprecated but its end of life is not until June 30, 2018.  It is being
included because the following browsers will stop working when it is removed: Chrome < 22, Firefox < 27,
IE < 11, Safari < 7, iOS < 5, Android Browser < 5.

If you don't require backward compatibility, you can use the [Mozilla modern profile](https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility)
profile instead by including the environment variable `SSL_POLICY=Mozilla-Modern` to your container.
This profile is compatible with clients back to Firefox 27, Chrome 30, IE 11 on Windows 7,
Edge, Opera 17, Safari 9, Android 5.0, and Java 8.

Other policies available through the `SSL_POLICY` environment variable are [`Mozilla-Old`](https://wiki.mozilla.org/Security/Server_Side_TLS#Old_backward_compatibility)
and the [AWS ELB Security Policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html)
`AWS-TLS-1-2-2017-01`, `AWS-TLS-1-1-2017-01`, `AWS-2016-08`, `AWS-2015-05`, `AWS-2015-03` and `AWS-2015-02`.

Note that the `Mozilla-Old` policy should use a 1024 bits DH key for compatibility but this container generates
a 2048 bits key. The [Diffie-Hellman Groups](#diffie-hellman-groups) section details different methods of bypassing
this, either globally or per virtual-host.

The default behavior for the proxy when port 80 and 443 are exposed is as follows:

* If a container has a usable cert, port 80 will redirect to 443 for that container so that HTTPS
is always preferred when available.
* If the container does not have a usable cert, a 503 will be returned.

Note that in the latter case, a browser may get an connection error as no certificate is available
to establish a connection.  A self-signed or generic cert named `default.crt` and `default.key`
will allow a client browser to make a SSL connection (likely w/ a warning) and subsequently receive
a 500.

To serve traffic in both SSL and non-SSL modes without redirecting to SSL, you can include the
environment variable `HTTPS_METHOD=noredirect` (the default is `HTTPS_METHOD=redirect`).  You can also
disable the non-SSL site entirely with `HTTPS_METHOD=nohttp`, or disable the HTTPS site with
`HTTPS_METHOD=nohttps`. `HTTPS_METHOD` must be specified on each container for which you want to
override the default behavior.  If `HTTPS_METHOD=noredirect` is used, Strict Transport Security (HSTS)
is disabled to prevent HTTPS users from being redirected by the client.  If you cannot get to the HTTP
site after changing this setting, your browser has probably cached the HSTS policy and is automatically
redirecting you back to HTTPS.  You will need to clear your browser's HSTS cache or use an incognito
window / different browser.

By default, [HTTP Strict Transport Security (HSTS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) 
is enabled with `max-age=31536000` for HTTPS sites.  You can disable HSTS with the environment variable 
`HSTS=off` or use a custom HSTS configuration like `HSTS=max-age=31536000; includeSubDomains; preload`.  
*WARNING*: HSTS will force your users to visit the HTTPS version of your site for the `max-age` time - 
even if they type in `http://` manually.  The only way to get to an HTTP site after receiving an HSTS 
response is to clear your browser's HSTS cache.

### Basic Authentication Support

In order to be able to secure your virtual host, you have to create a file named as its equivalent VIRTUAL_HOST variable on directory
/etc/nginx/htpasswd/$VIRTUAL_HOST

```
$ docker run -d -p 80:80 -p 443:443 \
    -v /path/to/htpasswd:/etc/nginx/htpasswd \
    -v /path/to/certs:/etc/nginx/certs \
    -v /var/run/docker.sock:/tmp/docker.sock:ro \
    jwilder/nginx-proxy
```

You'll need apache2-utils on the machine where you plan to create the htpasswd file. Follow these [instructions](http://httpd.apache.org/docs/2.2/programs/htpasswd.html)

### Custom Nginx Configuration

If you need to configure Nginx beyond what is possible using environment variables, you can provide custom configuration files on either a proxy-wide or per-`VIRTUAL_HOST` basis.

#### Replacing default proxy settings

If you want to replace the default proxy settings for the nginx container, add a configuration file at `/etc/nginx/proxy.conf`. A file with the default settings would
look like this:

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

***NOTE***: If you provide this file it will replace the defaults; you may want to check the .tmpl file to make sure you have all of the needed options.

***NOTE***: The default configuration blocks the `Proxy` HTTP request header from being sent to downstream servers.  This prevents attackers from using the so-called [httpoxy attack](http://httpoxy.org).  There is no legitimate reason for a client to send this header, and there are many vulnerable languages / platforms (`CVE-2016-5385`, `CVE-2016-5386`, `CVE-2016-5387`, `CVE-2016-5388`, `CVE-2016-1000109`, `CVE-2016-1000110`, `CERT-VU#797896`).

#### Proxy-wide

To add settings on a proxy-wide basis, add your configuration file under `/etc/nginx/conf.d` using a name ending in `.conf`.

This can be done in a derived image by creating the file in a `RUN` command or by `COPY`ing the file into `conf.d`:

```Dockerfile
FROM jwilder/nginx-proxy
RUN { \
      echo 'server_tokens off;'; \
      echo 'client_max_body_size 100m;'; \
    } > /etc/nginx/conf.d/my_proxy.conf
```

Or it can be done by mounting in your custom configuration in your `docker run` command:

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/my_proxy.conf:/etc/nginx/conf.d/my_proxy.conf:ro -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy

#### Per-VIRTUAL_HOST

To add settings on a per-`VIRTUAL_HOST` basis, add your configuration file under `/etc/nginx/vhost.d`. Unlike in the proxy-wide case, which allows multiple config files with any name ending in `.conf`, the per-`VIRTUAL_HOST` file must be named exactly after the `VIRTUAL_HOST`.

In order to allow virtual hosts to be dynamically configured as backends are added and removed, it makes the most sense to mount an external directory as `/etc/nginx/vhost.d` as opposed to using derived images or mounting individual configuration files.

For example, if you have a virtual host named `app.example.com`, you could provide a custom configuration for that host as follows:

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/vhost.d:/etc/nginx/vhost.d:ro -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy
    $ { echo 'server_tokens off;'; echo 'client_max_body_size 100m;'; } > /path/to/vhost.d/app.example.com

If you are using multiple hostnames for a single container (e.g. `VIRTUAL_HOST=example.com,www.example.com`), the virtual host configuration file must exist for each hostname. If you would like to use the same configuration for multiple virtual host names, you can use a symlink:

    $ { echo 'server_tokens off;'; echo 'client_max_body_size 100m;'; } > /path/to/vhost.d/www.example.com
    $ ln -s /path/to/vhost.d/www.example.com /path/to/vhost.d/example.com

#### Per-VIRTUAL_HOST default configuration

If you want most of your virtual hosts to use a default single configuration and then override on a few specific ones, add those settings to the `/etc/nginx/vhost.d/default` file. This file
will be used on any virtual host which does not have a `/etc/nginx/vhost.d/{VIRTUAL_HOST}` file associated with it.

#### Per-VIRTUAL_HOST location configuration

To add settings to the "location" block on a per-`VIRTUAL_HOST` basis, add your configuration file under `/etc/nginx/vhost.d`
just like the previous section except with the suffix `_location`.

For example, if you have a virtual host named `app.example.com` and you have configured a proxy_cache `my-cache` in another custom file, you could tell it to use a proxy cache as follows:

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/vhost.d:/etc/nginx/vhost.d:ro -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy
    $ { echo 'proxy_cache my-cache;'; echo 'proxy_cache_valid  200 302  60m;'; echo 'proxy_cache_valid  404 1m;' } > /path/to/vhost.d/app.example.com_location

If you are using multiple hostnames for a single container (e.g. `VIRTUAL_HOST=example.com,www.example.com`), the virtual host configuration file must exist for each hostname. If you would like to use the same configuration for multiple virtual host names, you can use a symlink:

    $ { echo 'proxy_cache my-cache;'; echo 'proxy_cache_valid  200 302  60m;'; echo 'proxy_cache_valid  404 1m;' } > /path/to/vhost.d/app.example.com_location
    $ ln -s /path/to/vhost.d/www.example.com /path/to/vhost.d/example.com

#### Per-VIRTUAL_HOST location default configuration

If you want most of your virtual hosts to use a default single `location` block configuration and then override on a few specific ones, add those settings to the `/etc/nginx/vhost.d/default_location` file. This file
will be used on any virtual host which does not have a `/etc/nginx/vhost.d/{VIRTUAL_HOST}_location` file associated with it.

### Contributing

Before submitting pull requests or issues, please check github to make sure an existing issue or pull request is not already open.

#### Running Tests Locally

To run tests, you need to prepare the docker image to test which must be tagged `jwilder/nginx-proxy:test`:

    docker build -t jwilder/nginx-proxy:test .  # build the Debian variant image

and call the [test/pytest.sh](test/pytest.sh) script.

Then build the Alpine variant of the image:

    docker build -f Dockerfile.alpine -t jwilder/nginx-proxy:test .  # build the Alpline variant image

and call the [test/pytest.sh](test/pytest.sh) script again.


If your system has the `make` command, you can automate those tasks by calling:

    make test


You can learn more about how the test suite works and how to write new tests in the [test/README.md](test/README.md) file.

### Need help?

If you have questions on how to use the image, please ask them on the [Q&A Group](https://groups.google.com/forum/#!forum/nginx-proxy)
