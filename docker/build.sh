#!/bin/bash

# Build the webserver image
docker build -t equifax/webserver:latest -f equifax/webserver/Dockerfile ./equifax/webserver

# Build the webserver-creds image
# docker build -t equifax/webserver-creds:latest -f webserver-creds/Dockerfile .

# Build the database image
docker build -t equifax/database:latest -f equifax/database/Dockerfile ./equifax/database