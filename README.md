# SPYcy
Spies on you and records how much time processes run for.

# Dependencies
- sqlite3
- linux kernel

# Usage
You can either set suid for the binary so it runs with root privileges, or you can grant it necessary permissions with `setcap` command.
Keep in mind that if you move the executable file around you will need to set the permissions/suid again.
```sh
$ make
$ sudo make setcap
$ ./spycy
```

# Installation
```sh
$ make
$ cp spycy <somewhere in the $PATH>

# then choose how exactly you would like to grant permissions to the executable
$ sudo setcap cap_net_admin+ep `which spycy`
# or
$ sudo chown root:root `which spycy` && sudo chmod +s `which spycy`
```
