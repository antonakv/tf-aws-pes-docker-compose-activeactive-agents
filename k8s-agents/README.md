# tf-aws-pes-docker-compose-activeactive-agents k8s-agents
Terraform Enterprise k8s-agents

## Requirements

- Provisioned with `terraform apply` root folder of the main terraform code ../ of the repository

## Preparation

- Change folder to k8s-agents

```bash
cd k8s-agents
```

- Create variable values file called `terraform.tfvars`. Here is example file:

```
k8s_desired_agents         = 10
tfc_agent_docker_image_tag = "1.12"
```

## Run terraform code

- In the same folder you were before, run 

```bash
terraform init -upgrade
```

Example output:

```
% terraform init                  

Initializing the backend...
Initializing modules...
Downloading registry.terraform.io/terraform-aws-modules/eks/aws 18.30.2 for eks...
- eks in .terraform/modules/eks
- eks.eks_managed_node_group in .terraform/modules/eks/modules/eks-managed-node-group
- eks.eks_managed_node_group.user_data in .terraform/modules/eks/modules/_user_data
- eks.fargate_profile in .terraform/modules/eks/modules/fargate-profile
Downloading registry.terraform.io/terraform-aws-modules/kms/aws 1.0.2 for eks.kms...
- eks.kms in .terraform/modules/eks.kms
- eks.self_managed_node_group in .terraform/modules/eks/modules/self-managed-node-group
- eks.self_managed_node_group.user_data in .terraform/modules/eks/modules/_user_data

Initializing provider plugins...
- terraform.io/builtin/terraform is built in to Terraform
- Reusing previous version of hashicorp/kubernetes from the dependency lock file
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/tls from the dependency lock file
- Reusing previous version of hashicorp/cloudinit from the dependency lock file
- Installing hashicorp/tls v4.0.4...
- Installed hashicorp/tls v4.0.4 (signed by HashiCorp)
- Installing hashicorp/cloudinit v2.3.2...
- Installed hashicorp/cloudinit v2.3.2 (signed by HashiCorp)
- Installing hashicorp/kubernetes v2.22.0...
- Installed hashicorp/kubernetes v2.22.0 (signed by HashiCorp)
- Installing hashicorp/aws v5.10.0...
- Installed hashicorp/aws v5.10.0 (signed by HashiCorp)

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

- Run the `terraform apply`

Example output:

```
% terraform apply --auto-approve
data.terraform_remote_state.k8s-agents: Reading...
data.terraform_remote_state.k8s-agents: Read complete after 0s
module.eks.data.aws_partition.current: Reading...
module.eks.data.aws_default_tags.current: Reading...
module.eks.module.eks_managed_node_group["first"].data.aws_partition.current: Reading...
module.eks.module.kms.data.aws_partition.current: Reading...
module.eks.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.kms.data.aws_caller_identity.current: Reading...
module.eks.data.aws_default_tags.current: Read complete after 0s [id=aws]
module.eks.data.aws_caller_identity.current: Reading...
module.eks.module.eks_managed_node_group["first"].data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.module.eks_managed_node_group["first"].data.aws_caller_identity.current: Reading...
module.eks.module.kms.data.aws_partition.current: Read complete after 0s [id=aws]
module.eks.data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks.module.eks_managed_node_group["first"].data.aws_iam_policy_document.assume_role_policy[0]: Reading...
module.eks.module.eks_managed_node_group["first"].data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2560088296]
module.eks.data.aws_iam_policy_document.assume_role_policy[0]: Read complete after 0s [id=2764486067]
module.eks.module.kms.data.aws_caller_identity.current: Read complete after 0s [id=247711370364]
module.eks.module.eks_managed_node_group["first"].data.aws_caller_identity.current: Read complete after 0s [id=247711370364]
module.eks.data.aws_caller_identity.current: Read complete after 0s [id=247711370364]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_eks_cluster.k8s will be read during apply
  # (config refers to values not yet known)
 <= data "aws_eks_cluster" "k8s" {
      + arn                       = (known after apply)
      + certificate_authority     = (known after apply)
      + cluster_id                = (known after apply)
      + created_at                = (known after apply)
      + enabled_cluster_log_types = (known after apply)
      + endpoint                  = (known after apply)
      + id                        = (known after apply)
      + identity                  = (known after apply)
      + kubernetes_network_config = (known after apply)
      + name                      = (known after apply)
      + outpost_config            = (known after apply)
      + platform_version          = (known after apply)
      + role_arn                  = (known after apply)
      + status                    = (known after apply)
      + tags                      = (known after apply)
      + version                   = (known after apply)
      + vpc_config                = (known after apply)
    }

  # kubernetes_deployment.tfc-agent will be created
  + resource "kubernetes_deployment" "tfc-agent" {
      + id               = (known after apply)
      + wait_for_rollout = true

      + metadata {
          + generation       = (known after apply)
          + labels           = {
              + "app" = "tfc-agent"
            }
          + name             = "tfc-agent"
          + namespace        = (known after apply)
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + spec {
          + min_ready_seconds         = 0
          + paused                    = false
          + progress_deadline_seconds = 600
          + replicas                  = "10"
          + revision_history_limit    = 10

          + selector {
              + match_labels = {
                  + "app" = "tfc-agent"
                }
            }

          + template {
              + metadata {
                  + generation       = (known after apply)
                  + labels           = {
                      + "app" = "tfc-agent"
                    }
                  + name             = (known after apply)
                  + resource_version = (known after apply)
                  + uid              = (known after apply)
                }
              + spec {
                  + automount_service_account_token  = true
                  + dns_policy                       = "ClusterFirst"
                  + enable_service_links             = true
                  + host_ipc                         = false
                  + host_network                     = false
                  + host_pid                         = false
                  + hostname                         = (known after apply)
                  + node_name                        = (known after apply)
                  + restart_policy                   = "Always"
                  + scheduler_name                   = (known after apply)
                  + service_account_name             = (known after apply)
                  + share_process_namespace          = false
                  + termination_grace_period_seconds = 30

                  + container {
                      + image                      = "hashicorp/tfc-agent:latest"
                      + image_pull_policy          = (known after apply)
                      + name                       = "tfc-agent"
                      + stdin                      = false
                      + stdin_once                 = false
                      + termination_message_path   = "/dev/termination-log"
                      + termination_message_policy = (known after apply)
                      + tty                        = false

                      + env {
                          + name  = "TFC_AGENT_TOKEN"
                          + value = "e4Kyy2mgfkp5kA.atlasv1.vD2FWqfyRhh4nvUgIiTVPzttOL5TJRZG9yNSqzZrgS8TEPhy0Y0fbNkAQVcL6snE6PU"
                        }
                      + env {
                          + name  = "TFC_ADDRESS"
                          + value = "https://hsdftfe.my-domain.com"
                        }
                      + env {
                          + name  = "TFC_AGENT_LOG_LEVEL"
                          + value = "trace"
                        }

                      + resources {
                          + limits   = {
                              + "cpu"    = "1"
                              + "memory" = "512Mi"
                            }
                          + requests = {
                              + "cpu"    = "250m"
                              + "memory" = "50Mi"
                            }
                        }
                    }
                }
            }
        }
    }

  # kubernetes_namespace.tfc-agent will be created
  + resource "kubernetes_namespace" "tfc-agent" {
      + id                               = (known after apply)
      + wait_for_default_service_account = false

      + metadata {
          + generation       = (known after apply)
          + labels           = {
              + "app" = "tfc-agent"
            }
          + name             = "tfc-agent"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # module.eks.data.tls_certificate.this[0] will be read during apply
  # (config refers to values not yet known)
 <= data "tls_certificate" "this" {
      + certificates = (known after apply)
      + id           = (known after apply)
      + url          = (known after apply)
    }

  # module.eks.aws_cloudwatch_log_group.this[0] will be created
  + resource "aws_cloudwatch_log_group" "this" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + name              = "/aws/eks/axxxxxxxxx-hsdf-eks/cluster"
      + name_prefix       = (known after apply)
      + retention_in_days = 90
      + skip_destroy      = false
      + tags_all          = (known after apply)
    }

  # module.eks.aws_eks_addon.this["coredns"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name           = "coredns"
      + addon_version        = (known after apply)
      + arn                  = (known after apply)
      + cluster_name         = "axxxxxxxxx-hsdf-eks"
      + configuration_values = (known after apply)
      + created_at           = (known after apply)
      + id                   = (known after apply)
      + modified_at          = (known after apply)
      + tags_all             = (known after apply)
    }

  # module.eks.aws_eks_addon.this["kube-proxy"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name           = "kube-proxy"
      + addon_version        = (known after apply)
      + arn                  = (known after apply)
      + cluster_name         = "axxxxxxxxx-hsdf-eks"
      + configuration_values = (known after apply)
      + created_at           = (known after apply)
      + id                   = (known after apply)
      + modified_at          = (known after apply)
      + tags_all             = (known after apply)
    }

  # module.eks.aws_eks_addon.this["vpc-cni"] will be created
  + resource "aws_eks_addon" "this" {
      + addon_name           = "vpc-cni"
      + addon_version        = (known after apply)
      + arn                  = (known after apply)
      + cluster_name         = "axxxxxxxxx-hsdf-eks"
      + configuration_values = (known after apply)
      + created_at           = (known after apply)
      + id                   = (known after apply)
      + modified_at          = (known after apply)
      + tags_all             = (known after apply)
    }

  # module.eks.aws_eks_cluster.this[0] will be created
  + resource "aws_eks_cluster" "this" {
      + arn                       = (known after apply)
      + certificate_authority     = (known after apply)
      + cluster_id                = (known after apply)
      + created_at                = (known after apply)
      + enabled_cluster_log_types = [
          + "api",
          + "audit",
          + "authenticator",
        ]
      + endpoint                  = (known after apply)
      + id                        = (known after apply)
      + identity                  = (known after apply)
      + name                      = "axxxxxxxxx-hsdf-eks"
      + platform_version          = (known after apply)
      + role_arn                  = (known after apply)
      + status                    = (known after apply)
      + tags_all                  = (known after apply)
      + version                   = "1.24"

      + kubernetes_network_config {
          + ip_family         = (known after apply)
          + service_ipv4_cidr = (known after apply)
          + service_ipv6_cidr = (known after apply)
        }

      + timeouts {}

      + vpc_config {
          + cluster_security_group_id = (known after apply)
          + endpoint_private_access   = true
          + endpoint_public_access    = true
          + public_access_cidrs       = [
              + "0.0.0.0/0",
            ]
          + security_group_ids        = (known after apply)
          + subnet_ids                = [
              + "subnet-00305dae47ba3b02f",
              + "subnet-04cdb358133f4e500",
            ]
          + vpc_id                    = (known after apply)
        }
    }

  # module.eks.aws_iam_openid_connect_provider.oidc_provider[0] will be created
  + resource "aws_iam_openid_connect_provider" "oidc_provider" {
      + arn             = (known after apply)
      + client_id_list  = [
          + "sts.amazonaws.com",
        ]
      + id              = (known after apply)
      + tags            = {
          + "Name" = "axxxxxxxxx-hsdf-eks-eks-irsa"
        }
      + tags_all        = {
          + "Name" = "axxxxxxxxx-hsdf-eks-eks-irsa"
        }
      + thumbprint_list = (known after apply)
      + url             = (known after apply)
    }

  # module.eks.aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "eks.amazonaws.com"
                        }
                      + Sid       = "EKSClusterAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "axxxxxxxxx-hsdf-eks-cluster-"
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = "axxxxxxxxx-hsdf-eks-cluster"
          + policy = jsonencode(
                {
                  + Statement = [
                      + {
                          + Action   = [
                              + "logs:CreateLogGroup",
                            ]
                          + Effect   = "Deny"
                          + Resource = "*"
                        },
                    ]
                  + Version   = "2012-10-17"
                }
            )
        }
    }

  # module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
      + role       = (known after apply)
    }

  # module.eks.aws_security_group.cluster[0] will be created
  + resource "aws_security_group" "cluster" {
      + arn                    = (known after apply)
      + description            = "EKS cluster security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "axxxxxxxxx-hsdf-eks-cluster-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "axxxxxxxxx-hsdf-eks-cluster"
        }
      + tags_all               = {
          + "Name" = "axxxxxxxxx-hsdf-eks-cluster"
        }
      + vpc_id                 = "vpc-0148573dc670f821a"
    }

  # module.eks.aws_security_group.node[0] will be created
  + resource "aws_security_group" "node" {
      + arn                    = (known after apply)
      + description            = "EKS node shared security group"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "axxxxxxxxx-hsdf-eks-node-"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"                                   = "axxxxxxxxx-hsdf-eks-node"
          + "kubernetes.io/cluster/axxxxxxxxx-hsdf-eks" = "owned"
        }
      + tags_all               = {
          + "Name"                                   = "axxxxxxxxx-hsdf-eks-node"
          + "kubernetes.io/cluster/axxxxxxxxx-hsdf-eks" = "owned"
        }
      + vpc_id                 = "vpc-0148573dc670f821a"
    }

  # module.eks.aws_security_group_rule.cluster["egress_nodes_443"] will be created
  + resource "aws_security_group_rule" "cluster" {
      + description              = "Cluster API to node groups"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.cluster["egress_nodes_kubelet"] will be created
  + resource "aws_security_group_rule" "cluster" {
      + description              = "Cluster API to node kubelets"
      + from_port                = 10250
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 10250
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.cluster["ingress_nodes_443"] will be created
  + resource "aws_security_group_rule" "cluster" {
      + description              = "Node groups to cluster API"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["egress_cluster_443"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node groups to cluster API"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_https"] will be created
  + resource "aws_security_group_rule" "node" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Egress all HTTPS to internet"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_ntp_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Egress NTP/TCP to internet"
      + from_port                = 123
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 123
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_ntp_udp"] will be created
  + resource "aws_security_group_rule" "node" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Egress NTP/UDP to internet"
      + from_port                = 123
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "udp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 123
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_self_coredns_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["egress_self_coredns_udp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "udp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_443"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node groups"
      + from_port                = 443
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Cluster API to node kubelets"
      + from_port                = 10250
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 10250
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"] will be created
  + resource "aws_security_group_rule" "node" {
      + description              = "Node to node CoreDNS"
      + from_port                = 53
      + id                       = (known after apply)
      + prefix_list_ids          = []
      + protocol                 = "udp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 53
      + type                     = "ingress"
    }

  # module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0] will be created
  + resource "aws_eks_node_group" "this" {
      + ami_type               = "AL2_x86_64"
      + arn                    = (known after apply)
      + capacity_type          = (known after apply)
      + cluster_name           = "axxxxxxxxx-hsdf-eks"
      + disk_size              = (known after apply)
      + id                     = (known after apply)
      + instance_types         = [
          + "t3.large",
        ]
      + node_group_name        = (known after apply)
      + node_group_name_prefix = "axxxxxxxxx-hsdf-ng-1-"
      + node_role_arn          = (known after apply)
      + release_version        = (known after apply)
      + resources              = (known after apply)
      + status                 = (known after apply)
      + subnet_ids             = [
          + "subnet-00305dae47ba3b02f",
          + "subnet-04cdb358133f4e500",
        ]
      + tags                   = {
          + "Name" = "axxxxxxxxx-hsdf-ng-1"
        }
      + tags_all               = {
          + "Name" = "axxxxxxxxx-hsdf-ng-1"
        }
      + version                = "1.24"

      + launch_template {
          + id      = (known after apply)
          + name    = (known after apply)
          + version = (known after apply)
        }

      + scaling_config {
          + desired_size = 3
          + max_size     = 3
          + min_size     = 1
        }

      + timeouts {}
    }

  # module.eks.module.eks_managed_node_group["first"].aws_iam_role.this[0] will be created
  + resource "aws_iam_role" "this" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = "EKSNodeAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + description           = "EKS managed node group IAM role"
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "axxxxxxxxx-hsdf-ng-1-eks-node-group-"
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"] will be created
  + resource "aws_iam_role_policy_attachment" "this" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
      + role       = (known after apply)
    }

  # module.eks.module.eks_managed_node_group["first"].aws_launch_template.this[0] will be created
  + resource "aws_launch_template" "this" {
      + arn                    = (known after apply)
      + default_version        = (known after apply)
      + description            = "Custom launch template for axxxxxxxxx-hsdf-ng-1 EKS managed node group"
      + id                     = (known after apply)
      + latest_version         = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "first-"
      + tags_all               = (known after apply)
      + update_default_version = true
      + vpc_security_group_ids = (known after apply)

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_protocol_ipv6          = (known after apply)
          + http_put_response_hop_limit = 2
          + http_tokens                 = "required"
          + instance_metadata_tags      = (known after apply)
        }

      + monitoring {
          + enabled = true
        }

      + tag_specifications {
          + resource_type = "instance"
          + tags          = {
              + "Name" = "axxxxxxxxx-hsdf-ng-1"
            }
        }
      + tag_specifications {
          + resource_type = "network-interface"
          + tags          = {
              + "Name" = "axxxxxxxxx-hsdf-ng-1"
            }
        }
      + tag_specifications {
          + resource_type = "volume"
          + tags          = {
              + "Name" = "axxxxxxxxx-hsdf-ng-1"
            }
        }
    }

Plan: 32 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + kubectl_get_update_credentials = "aws eks --region eu-north-1 update-kubeconfig --name axxxxxxxxx-hsdf-eks"
  + namespace_id                   = (known after apply)
module.eks.aws_cloudwatch_log_group.this[0]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_iam_role.this[0]: Creating...
module.eks.aws_iam_role.this[0]: Creating...
module.eks.aws_security_group.node[0]: Creating...
module.eks.aws_security_group.cluster[0]: Creating...
module.eks.aws_cloudwatch_log_group.this[0]: Creation complete after 0s [id=/aws/eks/axxxxxxxxx-hsdf-eks/cluster]
module.eks.module.eks_managed_node_group["first"].aws_iam_role.this[0]: Creation complete after 1s [id=axxxxxxxxx-hsdf-ng-1-eks-node-group-20230731144114586300000001]
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Creating...
module.eks.aws_iam_role.this[0]: Creation complete after 1s [id=axxxxxxxxx-hsdf-eks-cluster-20230731144114586600000003]
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]: Creation complete after 0s [id=axxxxxxxxx-hsdf-ng-1-eks-node-group-20230731144114586300000001-20230731144115853400000005]
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"]: Creation complete after 0s [id=axxxxxxxxx-hsdf-ng-1-eks-node-group-20230731144114586300000001-20230731144115961400000006]
module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Creating...
module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Creating...
module.eks.module.eks_managed_node_group["first"].aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"]: Creation complete after 0s [id=axxxxxxxxx-hsdf-ng-1-eks-node-group-20230731144114586300000001-20230731144116036700000007]
module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]: Creation complete after 0s [id=axxxxxxxxx-hsdf-eks-cluster-20230731144114586600000003-20230731144116308800000009]
module.eks.aws_iam_role_policy_attachment.this["arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"]: Creation complete after 0s [id=axxxxxxxxx-hsdf-eks-cluster-20230731144114586600000003-20230731144116307400000008]
module.eks.aws_security_group.node[0]: Creation complete after 2s [id=sg-050dfa895545674cd]
module.eks.aws_security_group.cluster[0]: Creation complete after 2s [id=sg-075b65624c2c68194]
module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Creating...
module.eks.aws_security_group_rule.cluster["egress_nodes_443"]: Creating...
module.eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Creating...
module.eks.aws_security_group_rule.node["egress_ntp_tcp"]: Creating...
module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Creating...
module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Creating...
module.eks.aws_security_group_rule.node["egress_cluster_443"]: Creating...
module.eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Creating...
module.eks.aws_security_group_rule.node["egress_https"]: Creating...
module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]: Creation complete after 0s [id=sgrule-670930854]
module.eks.aws_security_group_rule.node["egress_ntp_tcp"]: Creation complete after 0s [id=sgrule-113645571]
module.eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Creating...
module.eks.aws_security_group_rule.node["ingress_cluster_443"]: Creating...
module.eks.aws_security_group_rule.cluster["egress_nodes_kubelet"]: Creation complete after 1s [id=sgrule-2437453737]
module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]: Creation complete after 1s [id=sgrule-4140340282]
module.eks.aws_security_group_rule.node["egress_ntp_udp"]: Creating...
module.eks.aws_security_group_rule.cluster["egress_nodes_443"]: Creation complete after 1s [id=sgrule-2174090072]
module.eks.aws_security_group_rule.node["egress_cluster_443"]: Creation complete after 1s [id=sgrule-1743747893]
module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]: Creation complete after 2s [id=sgrule-1385641941]
module.eks.aws_security_group_rule.node["egress_self_coredns_tcp"]: Creation complete after 3s [id=sgrule-2174096538]
module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]: Creation complete after 3s [id=sgrule-3348526901]
module.eks.aws_security_group_rule.node["egress_https"]: Creation complete after 4s [id=sgrule-3642238237]
module.eks.aws_security_group_rule.node["egress_self_coredns_udp"]: Creation complete after 4s [id=sgrule-267491068]
module.eks.aws_security_group_rule.node["ingress_cluster_443"]: Creation complete after 5s [id=sgrule-647174620]
module.eks.aws_security_group_rule.node["egress_ntp_udp"]: Creation complete after 4s [id=sgrule-2019048718]
module.eks.aws_eks_cluster.this[0]: Creating...
module.eks.aws_eks_cluster.this[0]: Still creating... [10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [1m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [2m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [3m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [4m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [5m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [6m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [7m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m0s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m10s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m20s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m30s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m40s elapsed]
module.eks.aws_eks_cluster.this[0]: Still creating... [8m50s elapsed]
module.eks.aws_eks_cluster.this[0]: Creation complete after 8m53s [id=axxxxxxxxx-hsdf-eks]
module.eks.data.tls_certificate.this[0]: Reading...
data.aws_eks_cluster.k8s: Reading...
module.eks.module.eks_managed_node_group["first"].aws_launch_template.this[0]: Creating...
data.aws_eks_cluster.k8s: Read complete after 0s [id=axxxxxxxxx-hsdf-eks]
module.eks.data.tls_certificate.this[0]: Read complete after 1s [id=5007ea61dfb4fcd4db18c0c232d56bef3b07d3dc]
module.eks.aws_iam_openid_connect_provider.oidc_provider[0]: Creating...
kubernetes_namespace.tfc-agent: Creating...
module.eks.module.eks_managed_node_group["first"].aws_launch_template.this[0]: Creation complete after 1s [id=lt-0c2e98cfcea0cbbc7]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Creating...
module.eks.aws_iam_openid_connect_provider.oidc_provider[0]: Creation complete after 0s [id=arn:aws:iam::247711370364:oidc-provider/oidc.eks.eu-north-1.amazonaws.com/id/7D5131173B5A791816FE3DE3314B9FB3]
kubernetes_namespace.tfc-agent: Creation complete after 1s [id=tfc-agent]
kubernetes_deployment.tfc-agent: Creating...
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [10s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [10s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [20s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [20s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [30s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [30s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [40s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [40s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [50s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [50s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m0s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [1m0s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m10s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [1m10s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m20s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [1m20s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m30s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [1m30s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m40s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [1m40s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [1m50s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [1m50s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [2m0s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [2m0s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [2m10s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [2m10s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [2m20s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [2m20s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [2m30s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [2m30s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [2m40s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [2m40s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [2m50s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [2m50s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [3m0s elapsed]
kubernetes_deployment.tfc-agent: Still creating... [3m0s elapsed]
kubernetes_deployment.tfc-agent: Creation complete after 3m6s [id=tfc-agent/tfc-agent]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [3m10s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Still creating... [3m20s elapsed]
module.eks.module.eks_managed_node_group["first"].aws_eks_node_group.this[0]: Creation complete after 3m21s [id=axxxxxxxxx-hsdf-eks:axxxxxxxxx-hsdf-ng-1-2023073114501582190000000c]
module.eks.aws_eks_addon.this["vpc-cni"]: Creating...
module.eks.aws_eks_addon.this["coredns"]: Creating...
module.eks.aws_eks_addon.this["kube-proxy"]: Creating...
module.eks.aws_eks_addon.this["kube-proxy"]: Creation complete after 4s [id=axxxxxxxxx-hsdf-eks:kube-proxy]
module.eks.aws_eks_addon.this["coredns"]: Still creating... [10s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [10s elapsed]
module.eks.aws_eks_addon.this["coredns"]: Creation complete after 14s [id=axxxxxxxxx-hsdf-eks:coredns]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [20s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [30s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [40s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [50s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Still creating... [1m0s elapsed]
module.eks.aws_eks_addon.this["vpc-cni"]: Creation complete after 1m5s [id=axxxxxxxxx-hsdf-eks:vpc-cni]

Apply complete! Resources: 32 added, 0 changed, 0 destroyed.

Outputs:

kubectl_get_update_credentials = "aws eks --region eu-north-1 update-kubeconfig --name axxxxxxxxx-hsdf-eks"
namespace_id = "tfc-agent"
```

## Check tfc-agents deployment in K8S

- In the local machine terminal run text from the terraform output called `kubectl_get_update_credentials`

Example output:

```
% aws eks --region eu-north-1 update-kubeconfig --name user-2y64g5-eks
Added new context arn:aws:eks:eu-north-1:247711370364:cluster/user-2y64g5-eks to /Users/user/.kube/config
```

- In the local machine terminal run `kubectl describe deployment tfc-agent -n tfc-agent`

Example output:

```

k8s-agents % kubectl describe deployment tfc-agent -n tfc-agent
Name:                   tfc-agent
Namespace:              tfc-agent
CreationTimestamp:      Wed, 02 Aug 2023 09:12:24 +0200
Labels:                 app=tfc-agent
Annotations:            deployment.kubernetes.io/revision: 1
Selector:               app=tfc-agent
Replicas:               10 desired | 10 updated | 10 total | 10 available | 0 unavailable
StrategyType:           RollingUpdate
MinReadySeconds:        0
RollingUpdateStrategy:  25% max unavailable, 25% max surge
Pod Template:
  Labels:  app=tfc-agent
  Containers:
   tfc-agent:
    Image:      hashicorp/tfc-agent:latest
    Port:       <none>
    Host Port:  <none>
    Limits:
      cpu:     1
      memory:  512Mi
    Requests:
      cpu:     250m
      memory:  50Mi
    Environment:
      TFC_AGENT_TOKEN:      lbSyhsTib9G08A.atlasv1.GlCbK9j91mnj8qSjVROd9lcq8O3HIHsdU5IYVvFFxkMw4qgxP9jJdIaFePyOzgBk1ZM
      TFC_ADDRESS:          https://2y64g5tfe.userhere.cc
      TFC_AGENT_LOG_LEVEL:  trace
    Mounts:                 <none>
  Volumes:                  <none>
Conditions:
  Type           Status  Reason
  ----           ------  ------
  Available      True    MinimumReplicasAvailable
  Progressing    True    NewReplicaSetAvailable
OldReplicaSets:  <none>
NewReplicaSet:   tfc-agent-794985fc98 (10/10 replicas created)
Events:
  Type    Reason             Age   From                   Message
  ----    ------             ----  ----                   -------
  Normal  ScalingReplicaSet  38m   deployment-controller  Scaled up replica set tfc-agent-794985fc98 to 10
```
