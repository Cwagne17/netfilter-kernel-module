# netfilter-kernel-module

COSC 458_001 Homework 2 Question 5.

```
Write loadable kernel modules to set the followings firewall rules:
(a) Only block telnet traffic.
(b) Only block UDP packages on port > 2500
(c) Only allow web traffic.
(d) Only block web traffic from a certain domain, e.g., google.com, and allow all other traffic.
```

## Firewall A

```console
make args="firewall-a"
sudo insmod firewall-a.ko
```

```console
telnet 127.0.0.1 23
```

```console
$ tail /var/log/syslog
Dec  5 15:24:49 VM kernel: [  646.880246] Firewall Module loaded.
Dec  5 15:24:56 VM kernel: [  653.742914] Firewall A -- Dropping TelNet packet
Dec  5 15:24:57 VM kernel: [  654.777332] Firewall A -- Dropping TelNet packet
```

```console
sudo rmmod firewall-a.ko
make clean args="firewall-a"
```

## Firewall B

```console
make args="firewall-b"
sudo insmod firewall-b.ko
```

Opened up the firefox browser.

```console
$ tail /var/log/syslog
Dec  5 16:23:14 VM kernel: [  964.820425] Firewall B -- Dropping UDP packet
```

```console
sudo rmmod firewall-b.ko
make clean args="firewall-b"
```

## Firewall C

## Firewall D

## References

<https://github.com/mahdi2019/firewall>
<https://github.com/torvalds/linux/blob/master/include/linux/socket.h>
