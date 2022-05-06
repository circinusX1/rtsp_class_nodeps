# rtsp_class_nodeps
RTSP C++ CLASS, No dependencies. Basic authentication

```
  ./make.sh
  rtsp_class_nodeps  rtsp://192.168.1.106:554/onvif0 admin:dg20160404
  OR
  rtsp_class_nodeps  rtsp://IP/STREAM 
```

# on asecond terminal

```
ffplay /tmp/movie_pipe.mov
 try also
mplayer -cache 600 -cache-min 99 /tmp/movie_pipe.mov 

```
