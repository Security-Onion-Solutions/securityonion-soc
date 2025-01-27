Example directory listing of a PCAP file being uploaded for import:

```
-rw-r--r--  1 jertel jertel    1355 Jan 27 18:15  hdcp_authentication_sample.pcap
```

Example POST request, with some of the noteworthy headers shown:

```
POST /connect/gridmembers/manager_standalone/import

...
content-length: 1584
content-type: multipart/form-data; boundary=----WebKitFormBoundaryaKfZhnMSKrgA9HJh
...

------WebKitFormBoundaryaKfZhnMSKrgA9HJh
Content-Disposition: form-data; name="attachment"; filename="hdcp_authentication_sample.pcap"
Content-Type: application/vnd.tcpdump.pcap

<< raw bytes >>

------WebKitFormBoundaryaKfZhnMSKrgA9HJh--
```