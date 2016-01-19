##### Go VirtualBox vboxsf sendfile bug workaround

If you serve static content from a shared folder you might have run into a
vboxsf file corruption bug. This hack disables the sendfile syscall for
the go process which will force the standard library to fallback to userland
buffered IO.

References:  
[Ticket #9069 shared folder doesn't seem to update](https://www.virtualbox.org/ticket/9069)  
[net: Add ability to disable sendfile](https://github.com/golang/go/issues/9694)

##### Usage

Save [disable_sendfile_vbox_linux.go](disable_sendfile_vbox_linux.go) to somewhere in your go project.
Or do
```go
import (
	_ "github.com/wader/disable_sendfile_vbox_linux"
}
```
in a source file.

##### Docker or other containers

If your running in a Linux container (boot2docker, docker-machine vbox, etc)
you will need to give the container the capability to use `seccomp`.

`docker run --cap-add=SYS_ADMIN ...`

docker-compose:
```
service:
	cap_add:
		- SYS_ADMIN
```

##### License

Public domain. Your free to do whatever you want.
