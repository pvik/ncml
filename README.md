# NCML 

A Simple service to allow NCM Script Execution operations via Rest API

## Sample Config

```toml
port = 3001

workers = 1

[jwt-auth]
    enabled = true
	secret = "abc"
	
# Setup Credential sets 
[credentials]
	
    [credentials."cred-set-1"]
    username = "test-user"
    password = "abc"
	
	[credentials."cred-set-2"]
    username = "test-user-2"
    password = "def"

[db]
host = "localhost"
port = 5432
ssl-mode = false
username = "postgres"
password = "docker"
dbname = "ncml"

[log]
format = "text" # valid values are text or json
output = "term" # valid values are term or file
#log-directory = "./logs/" # needed if writing logs to a file
level = "debug"
```

## Deploy using Docker

```
# docker run --rm -p 3000:3000 -v ./config.toml:/app/configs/config.toml pvik/ncml:latest
```

## Usage
