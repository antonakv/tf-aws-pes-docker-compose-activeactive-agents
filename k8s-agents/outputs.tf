output "kubectl_get_update_credentials" {
  description = "Run to retrieve the access credentials for the k8s and configure kubectl"
  value       = "aws eks --region ${data.terraform_remote_state.k8s-agents.outputs.region} update-kubeconfig --name ${data.terraform_remote_state.k8s-agents.outputs.friendly_name_prefix}-eks"
}
output "namespace_id" {
  value = kubernetes_namespace.tfc-agent.id
}
