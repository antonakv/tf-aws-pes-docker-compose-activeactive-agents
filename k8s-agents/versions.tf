terraform {
  required_version = ">= 1.2.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.39.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.2.3"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.14.0"
    }
  }
}
