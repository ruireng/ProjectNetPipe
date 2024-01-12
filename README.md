# IK2206 Internet Security and Privacy - Project: NetPipe
NetPipe is a secure network application providing basic communication services. It sets up a TCP connection between two hosts and forwards the data between system I/O and the TCP connection. This application is very similar to "netcat" or "nc".

NetPipe establishes a secure tunnel for communication between two computers. In this way, NetPipe can serve as a general-purpose VPN application that allows you to connect computers across the network in a secure way.

After correctly setting up the project, it will be possible for two terminal windows (either on the same computer, or on different computers) to communicate with each other.

![alt text](https://github.com/ruireng/ProjectNetPipe/blob/main/Resources/example.png)

In order for NetPipe to work properly, you will need to create keys and certifications for the client, server and a certificate authority (CA). OpenSSL is a software that can handle those tasks. It normally comes pre-installed on MacOS and Linux. If you use Windows, there is a pre-compiled binary version in your Git installation. You can also find and use pre-compiled OpenSSL binaries from the Internet.

## Creating Certificates Using OpenSSL
1. Create a CA and its self-signed certificate.

```
OpenSSL> req -new -x509 -newkey rsa:2048 -keyout your_CA_privatekey.pem
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Then, follow OpenSSL's instructions. Make sure to fill in reasonable values for the Distinguished Name (DN).

2. Save the certificate (the output) in a file, your_CA_certificate.pem. The output looks something like this:

<Insert image here>

## Project Setup
1. Clone the repository.
2. 
