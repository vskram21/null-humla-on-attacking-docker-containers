# Attacking Docker Containers

---

### About Me
#### Satheesh Kumar Varatharajan

- Working as Security Consultant @ DevOn (formally Prowareness)
- Over 8 years of experience in Information Security
- OSCP Certified 

---

## Agenda 

- Setting up AWS EC2 instance
- Introduction to Docker 
- Running Basic docker commands
- Building blocks of Docker
- Creating Docker images
- Introduction to Docker compose
- Scanning docker images for security vulnerabilities using tools
- Attacking Docker
  <!-- - Enumerating Docker containers
  - Using code execution to gain access to host machine
    - Using docker.sock file mounted on host machine
    - Adding user to host machine leveraging volume mount misconfiguration
  - Case study of CVE-2019-5736 -->
- Hardening Docker

---

### Setting up EC2 instance

- Launch a free tier AWS EC2 instance with ubuntu 18.04 LTS
- Download the .pem file
- Convert to .ppk file using PuttyGen
- Load it in Putty and connect to the EC2 instance 
- Run the below script to install docker
  
```
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu
exit 
```

---

### Introduction to Docker

- Open platform for developing, shipping and running applications 
- Separates application from infrastructure 
- Solves the *It works on my machine* problem 
- Reduces the delay between writing code and running it in production 

----

### Basic commands

```
docker search
docker pull
docker run
docker exec
docker ps 
docker inspect
docker kill
docker rm 
docker rmi
docker logs 
docker network
```

----

### Docker Terminology

- Docker image
- Docker Container
- Docker Registry
- Docker hub

----

### Docker one liners for cleanup

    docker container rm -f $(docker container ls -aq) # stops and removes all containers
    docker rmi <image name>
    rm -rf /var/lib/docker

---

### Building blocks of Docker

- Namespace  - Isolation capabilities (mounting, IPC, PID, Network)
- Cgroups  - Grouping process (CPU, memory, n/w bandwidth)
- Capabilities  - Provides ability to limit certain capabilities for eg, chown, route
- Seccomp - Sanboxing by allowing and disallowing SYS calls
- AppArmor - Allows for fine grained permissions

----

### Namespaces 

- Linux provides the following namespaces,
       Namespace   Constant          Isolates
       Cgroup      CLONE_NEWCGROUP   Cgroup root directory
       IPC         CLONE_NEWIPC      System V IPC, POSIX message queues
       Network     CLONE_NEWNET      Network devices, stacks, ports, etc.
       Mount       CLONE_NEWNS       Mount points
       PID         CLONE_NEWPID      Process IDs
       User        CLONE_NEWUSER     User and group IDs
       UTS         CLONE_NEWUTS      Hostname and NIS domain name

- The directory **/proc/sys/user** has the number of namespaces that could be created
- Namespace of the process could be viewed by  `ls -l  /proc/pid/ns`
  
----

### Cgroups

- Limit usage of CPU, memory, network and IOPS
- Could be used to restrict resources to any process in linux
       # mkdir /sys/fs/cgroup/memory/groupname
       # echo 100000000 > /sys/fs/cgroup/memory/groupname/memory.limit_in_bytes
       # echo pid > /sys/fs/cgroup/memory/groupname/cgroup.procs
       # cgexec -g groupname /bin/bash 
 
----

### Capabilities
 - Provided fine grained permissions
 - Below are some of the capabilities, 
        CAP_CHOWN               change ownership of files/directories
        CAP_DAC_OVERRIDE        bypass rwx checks
        CAP_KILL                bypass permission checks to kill a process
        CAP_NET_ADMIN           make various changes to network config like route
        CAP_NET_BIND_SERVICE    bind privileged ports (less than 1024)
        CAP_NET_RAW             use RAW sockets, bind to any address
        CAP_SETGID              arbitrary manipulation of process GIDs
        CAP_SYS_ADMIN           perform sysadmin operations, mount, umount, etc.,
        CAP_SYSLOG              manipulate system logs
        CAP_SETUID              manipulate, forge UIDs

----

### Seccomp

- Linux kernel sandbox
- Limit SYS calls 
- Docker could leverage --security-opt <seccomp profile> for fine grained control
- seccomp could be [bypassed if ptrace is enabled](https://gist.github.com/thejh/8346f47e359adecd1d53) 

----

### Apparmor

- Application Armor (AppArmor) is a Linux Security Module (LSM)
- Offers much more fine grained controls, for eg, restrict file operations for specific paths
- 'deny' rule has precedence over 'allow' meaning 'deny' rule cannot be overwritten

----

### Writing Dockerfile

- Understanding basic usage
       FROM
       ENV
       EXPOSE
       ADD
       COPY
       VOLUME
       RUN
       USER
       CHDIR
       WORKDIR
       ENTRYPOINT

---

### Docker Compose

- Makes it easier to run multiple containers 
- Very useful to scale up and down easily
  
```
sudo curl -L https://github.com/docker/compose/releases/download/1.24.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

----

### Setting up Wordpress with Docker Compose

- follow instructions at https://docs.docker.com/compose/wordpress/

---

### Demo and Hands-on Attacking Dockers

- Using code execution to gain access to host machine
    - Using docker.sock file mounted on host machine
    - Adding user to host machine leveraging volume mount misconfiguration
-  Case study of CVE-2019-5736

----

### Scenario 1: From code execution to reverse shell

 - docker.sock file mounted in the docker container

----

### Scenario 2: From code execution to reverse shell

- Adding user to host machine leveraging volume mount misconfiguration

----

### Case study of CVE-2019-5736

- Recent container escape technique
- allows attackers to override host runc binary 
- docker versions < 18.09.2

---

### Securing Docker Containers 

- Use the images from reliable sources which are free from vulnerabilities
- Do not run your containers as root
- Follow best practises for Dockerfile
- Change default credentials 
- Limit the access to Docker service
- Follow CIS, NIST 800-190, and docker-bench-security standards.

---

### References

- Docker Documentations 
- https://github.com/docker/labs
- https://d3oypxn00j2a10.cloudfront.net/assets/img/Docker%20Security/WP_Intro_to_container_security_03.20.2015.pdf
- https://nvd.nist.gov/vuln/detail/CVE-2019-5736
- https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html
- https://gist.github.com/FrankSpierings/5c79523ba693aaa38bc963083f48456c#file-readme-md
- https://www.youtube.com/watch?v=ru7GicI5iyI
- https://github.com/genuinetools/amicontained/blob/master/main.go
- https://github.com/makash/linux-container-security-docs
- https://github.com/madhuakula/introduction-to-containers-using-docker

---