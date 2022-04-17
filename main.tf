terraform {
  required_version = ">= 0.13"

  backend "s3" {
    bucket         = "final-demo-jctbucket-18"
    key            = "terraform.tfstate"
    region         = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}
