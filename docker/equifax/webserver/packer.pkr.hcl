packer {
  required_plugins {
    docker = {
      version = ">= 1.0.8"
      source  = "github.com/hashicorp/docker"
    }
  }
}

source "docker" "equifax-webserver" {
  image  = "equifax/webserver:latest"
  commit = true
}

build {
  name = "equifax/webserver-packer"
  sources = [
    "source.docker.equifax-webserver"
  ]
}
