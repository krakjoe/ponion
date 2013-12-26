ponion
======

```
ponion (0.0.1) (built: Dec 26 2013 09:36:48)
        -h              show this help menu
        -n              do not load any php.ini file
        -c              load a specific php.ini file, -c/my/php.ini
        -d              define ini entry on command line, -dmemory_limit=4G
        -z              load zend_extension, -z/path/to/zendext.so
        -p              sets the listening port to accept connections, -p12000
        -a              set the interface address to bind too, -a127.0.0.1
        -t              set the socket timeout in milliseconds, -t5000
        -D              set the document root (chdir), -D.
        -T              set the maximum number of threads, -T16
        -K              set the SSL key, -K/path/to/cert.key
        -C              set the SSL certification, -C/path/to/cert.pem
```

onion is a rather cool HTTP and TCP server creation library: https://github.com/davidmoreno/onion/

PHP is everything else: http://php.net

```
Server Software:        libonion
Server Hostname:        127.0.0.1
Server Port:            12000

Document Path:          /
Document Length:        2558 bytes

Concurrency Level:      5
Time taken for tests:   1.502 seconds
Complete requests:      1000
Failed requests:        0
Write errors:           0
Total transferred:      2697000 bytes
HTML transferred:       2558000 bytes
Requests per second:    665.67 [#/sec] (mean)
Time per request:       7.511 [ms] (mean)
Time per request:       1.502 [ms] (mean, across all concurrent requests)
```

Above is a twitter/bootstrap based bare minimum Silex application using twig based templates, Apache (nts) got to around 35
