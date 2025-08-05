# Сopytrading

## How to setup plugin and run on remote server?

# Setup Guide

## Prerequisites
- Debian or Ubuntu
- Docker and Docker Compose
- Git

## 1. Pull repo on your server

```
git clone <YOUR GITHUB/GITLAB REPO>
cd copytrading
```

## 2. Start Services

First, start the services using Docker Compose, it has both db/infra and backend services:

```
# create shared network in docker
docker network create shared-network
# start running service with docker compose
make up
# stop running service with docker compose
make down
```