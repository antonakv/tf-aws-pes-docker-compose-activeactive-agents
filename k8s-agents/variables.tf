variable "k8s_desired_agents" {
  type = number
}
variable "tfc_agent_docker_image_tag" {
  type        = string
  description = "hashicorp/tfc-agent image tag"
}
