#!/bin/bash
app="server"
docker build -t ${app} .
sudo docker run -it -p 5000 -d ${app}  
