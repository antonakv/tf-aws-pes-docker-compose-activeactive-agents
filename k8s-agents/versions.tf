terraform {
  required_version = ">= 1.5.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.9.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "= 2.22.0"
    }
  }
}
