# tf-aws-pes-docker-compose-activeactive-agents
Terraform Enterprise FDO PES Docker Compose Active Active Agents

## Requirements

- Hashicorp terraform version 1.5.3 installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in `.aws/credentials` file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

- Configured CloudFlare DNS zone for domain `my-domain-here.com`
[Cloudflare DNS zone setup](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/)

- SSL certificate and SSL key files for the corresponding domain name
[Certbot manual](https://certbot.eff.org/instructions)

- Created Amazon EC2 key pair for Linux instance
[Amazon EC2 key pairs and Linux instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)

- Packer AWS AMI image built using the repository `antonakv/packer-aws-ubuntujammy-tfe-fdo`

- Packer AWS AMI image built using the repository `antonakv/packer-aws-ubuntujammy-terraform-agent`



## Preparation

- Login to the `quai.io`

- In the Account settings click `Generate Encrypted Password`

- Add variable value to `terraform.tfvars` called `docker_quaiio_token` from `-p="token_value_here"` generated on the previous step.

- Create variable values file called `terraform.tfvars`. Here is example file, values have to be modified before terraform run:

```
region                  = "eu-north-1"
tfe_license_path        = "upload/license.lic"
cidr_vpc                = "10.5.0.0/16"
cidr_subnet_private_1   = "10.5.1.0/24"
cidr_subnet_private_2   = "10.5.2.0/24"
cidr_subnet_public_1    = "10.5.3.0/24"
cidr_subnet_public_2    = "10.5.4.0/24"
key_name                = "key_region_name_here"
aws_ami                 = "ami-xxxxxxxxxxxxxxxxx"
agent_ami               = "ami-xxxxxxxxxxxxxxxxx"
db_instance_type        = "db.t3.xlarge"
instance_type           = "t3.2xlarge"
instance_type_redis     = "cache.t3.medium"
instance_type_agent     = "t3.medium"
tfe_hostname            = "tfe.NAME_HERE.cc"
postgres_db_name        = "mydbtfe"
postgres_engine_version = "14.4"
postgres_username       = "postgres"
ssl_cert_path           = "cert.pem"
ssl_key_path            = "privkey.pem"
ssl_chain_path          = "chain.pem"
ssl_fullchain_cert_path = "fullchain.pem"
domain_name             = "NAME_HERE.cc"
cloudflare_zone_id      = "yyyyyyyyyyyyyyyyyyy"
cloudflare_api_token    = "yyyyyyyyyyyyyyyyyyy"
lb_ssl_policy           = "ELBSecurityPolicy-TLS13-1-3-2021-06"
tfe_tls_version         = "tls_1_3"
aws_az_1                = "eu-north-1b"
aws_az_2                = "eu-north-1c"
docker_quaiio_login     = "xxxxxxxxxxx"
docker_quaiio_token     = "xxxxxxxxxxx"
tfe_quaiio_tag          = "3bc2fb8"
asg_min_agents          = 0
asg_max_agents          = 0
asg_desired_agents      = 0
asg_min_nodes           = 3
asg_max_nodes           = 3
asg_desired_nodes       = 3
agent_token             = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## Provisioning

- Run the `terraform init`

Example output:

```
% terraform init                  

Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of hashicorp/random from the dependency lock file
- Reusing previous version of hashicorp/template from the dependency lock file
- Reusing previous version of cloudflare/cloudflare from the dependency lock file
- Reusing previous version of hashicorp/local from the dependency lock file
- Installing hashicorp/aws v5.9.0...
- Installed hashicorp/aws v5.9.0 (signed by HashiCorp)
- Installing hashicorp/random v3.5.1...
- Installed hashicorp/random v3.5.1 (signed by HashiCorp)
- Installing hashicorp/template v2.2.0...
- Installed hashicorp/template v2.2.0 (signed by HashiCorp)
- Installing cloudflare/cloudflare v4.10.0...
- Installed cloudflare/cloudflare v4.10.0 (self-signed, key ID C76001609EE3B136)
- Installing hashicorp/local v2.4.0...
- Installed hashicorp/local v2.4.0 (signed by HashiCorp)

Partner and community providers are signed by their developers.
If you'd like to know more about provider signing, you can read about it here:
https://www.terraform.io/docs/cli/plugins/signing.html

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
data.local_sensitive_file.sslchain: Reading...
data.local_sensitive_file.sslkey: Reading...
data.local_sensitive_file.sslchain: Read complete after 0s [id=35bea03aecd55ca4d525c6b0a45908a19c6986f9]
data.local_sensitive_file.sslkey: Read complete after 0s [id=01e293ac04d434108c6e14d05c13404d1217a6b9]
data.local_sensitive_file.sslcert: Reading...
data.local_sensitive_file.sslcert: Read complete after 0s [id=ddcbc040de65e147fed005d4cdaa5b6f04a85452]
data.aws_iam_policy_document.cloudwatch_logs: Reading...
data.aws_iam_policy_document.tfe_asg_discovery: Reading...
data.aws_iam_policy_document.tfe_asg_discovery: Read complete after 0s [id=3912694501]
data.aws_iam_policy_document.cloudwatch_logs: Read complete after 0s [id=3508293357]
data.aws_iam_policy_document.instance_role: Reading...
data.aws_iam_policy_document.instance_role: Read complete after 0s [id=2851119427]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_iam_policy_document.secretsmanager will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "secretsmanager" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "secretsmanager:GetSecretValue",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
              + (known after apply),
              + (known after apply),
              + (known after apply),
            ]
          + sid       = "AllowSecretsManagerSecretAccess"
        }
    }

  # data.aws_iam_policy_document.tfe_data will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "tfe_data" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "s3:GetBucketLocation",
              + "s3:ListBucket",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
            ]
          + sid       = "AllowS3ListBucketData"

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
      + statement {
          + actions   = [
              + "s3:DeleteObject",
              + "s3:GetObject",
              + "s3:PutObject",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
            ]
          + sid       = "AllowS3ManagementData"

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
    }

  # data.aws_instances.tfc_agent will be read during apply
  # (config refers to values not yet known)
 <= data "aws_instances" "tfc_agent" {
      + id                   = (known after apply)
      + ids                  = (known after apply)
      + instance_state_names = [
          + "running",
        ]
      + instance_tags        = {
          + "Name" = (known after apply)
        }
      + ipv6_addresses       = (known after apply)
      + private_ips          = (known after apply)
      + public_ips           = (known after apply)

      + filter {
          + name   = "instance.group-id"
          + values = [
              + (known after apply),
            ]
        }
    }

  # data.aws_instances.tfe will be read during apply
  # (config refers to values not yet known)
 <= data "aws_instances" "tfe" {
      + id                   = (known after apply)
      + ids                  = (known after apply)
      + instance_state_names = [
          + "running",
        ]
      + instance_tags        = {
          + "Name" = (known after apply)
        }
      + ipv6_addresses       = (known after apply)
      + private_ips          = (known after apply)
      + public_ips           = (known after apply)

      + filter {
          + name   = "instance.group-id"
          + values = [
              + (known after apply),
            ]
        }
    }

  # aws_acm_certificate.tfe will be created
  + resource "aws_acm_certificate" "tfe" {
      + arn                       = (known after apply)
      + certificate_body          = (sensitive value)
      + certificate_chain         = (sensitive value)
      + domain_name               = (known after apply)
      + domain_validation_options = (known after apply)
      + id                        = (known after apply)
      + key_algorithm             = (known after apply)
      + not_after                 = (known after apply)
      + not_before                = (known after apply)
      + pending_renewal           = (known after apply)
      + private_key               = (sensitive value)
      + renewal_eligibility       = (known after apply)
      + renewal_summary           = (known after apply)
      + status                    = (known after apply)
      + subject_alternative_names = (known after apply)
      + tags_all                  = (known after apply)
      + type                      = (known after apply)
      + validation_emails         = (known after apply)
      + validation_method         = (known after apply)
    }

  # aws_autoscaling_group.tfc_agent will be created
  + resource "aws_autoscaling_group" "tfc_agent" {
      + arn                       = (known after apply)
      + availability_zones        = (known after apply)
      + default_cooldown          = (known after apply)
      + desired_capacity          = 0
      + force_delete              = false
      + force_delete_warm_pool    = false
      + health_check_grace_period = 900
      + health_check_type         = "EC2"
      + id                        = (known after apply)
      + launch_configuration      = (known after apply)
      + load_balancers            = (known after apply)
      + max_size                  = 3
      + metrics_granularity       = "1Minute"
      + min_size                  = 3
      + name                      = (known after apply)
      + name_prefix               = (known after apply)
      + predicted_capacity        = (known after apply)
      + protect_from_scale_in     = false
      + service_linked_role_arn   = (known after apply)
      + target_group_arns         = (known after apply)
      + vpc_zone_identifier       = (known after apply)
      + wait_for_capacity_timeout = "10m"
      + warm_pool_size            = (known after apply)

      + tag {
          + key                 = "Name"
          + propagate_at_launch = true
          + value               = (known after apply)
        }
    }

  # aws_autoscaling_group.tfe will be created
  + resource "aws_autoscaling_group" "tfe" {
      + arn                       = (known after apply)
      + availability_zones        = (known after apply)
      + default_cooldown          = (known after apply)
      + desired_capacity          = 3
      + force_delete              = false
      + force_delete_warm_pool    = false
      + health_check_grace_period = 5500
      + health_check_type         = "ELB"
      + id                        = (known after apply)
      + launch_configuration      = (known after apply)
      + load_balancers            = (known after apply)
      + max_size                  = 3
      + metrics_granularity       = "1Minute"
      + min_size                  = 3
      + name                      = (known after apply)
      + name_prefix               = (known after apply)
      + predicted_capacity        = (known after apply)
      + protect_from_scale_in     = false
      + service_linked_role_arn   = (known after apply)
      + target_group_arns         = (known after apply)
      + vpc_zone_identifier       = (known after apply)
      + wait_for_capacity_timeout = "10m"
      + warm_pool_size            = (known after apply)

      + tag {
          + key                 = "Name"
          + propagate_at_launch = true
          + value               = (known after apply)
        }
    }

  # aws_db_instance.tfe will be created
  + resource "aws_db_instance" "tfe" {
      + address                               = (known after apply)
      + allocated_storage                     = 20
      + allow_major_version_upgrade           = true
      + apply_immediately                     = true
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + backup_retention_period               = (known after apply)
      + backup_target                         = (known after apply)
      + backup_window                         = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + character_set_name                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_name                               = "mydbtfe"
      + db_subnet_group_name                  = (known after apply)
      + delete_automated_backups              = true
      + deletion_protection                   = false
      + endpoint                              = (known after apply)
      + engine                                = "postgres"
      + engine_version                        = "14.4"
      + engine_version_actual                 = (known after apply)
      + hosted_zone_id                        = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = (known after apply)
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t3.xlarge"
      + iops                                  = (known after apply)
      + kms_key_id                            = (known after apply)
      + latest_restorable_time                = (known after apply)
      + license_model                         = (known after apply)
      + listener_endpoint                     = (known after apply)
      + maintenance_window                    = (known after apply)
      + master_user_secret                    = (known after apply)
      + master_user_secret_kms_key_id         = (known after apply)
      + max_allocated_storage                 = 100
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + multi_az                              = (known after apply)
      + nchar_character_set_name              = (known after apply)
      + network_type                          = (known after apply)
      + option_group_name                     = (known after apply)
      + parameter_group_name                  = (known after apply)
      + password                              = (sensitive value)
      + performance_insights_enabled          = false
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = 5432
      + publicly_accessible                   = false
      + replica_mode                          = (known after apply)
      + replicas                              = (known after apply)
      + resource_id                           = (known after apply)
      + skip_final_snapshot                   = true
      + snapshot_identifier                   = (known after apply)
      + status                                = (known after apply)
      + storage_throughput                    = (known after apply)
      + storage_type                          = "gp2"
      + tags                                  = (known after apply)
      + tags_all                              = (known after apply)
      + timezone                              = (known after apply)
      + username                              = "postgres"
      + vpc_security_group_ids                = (known after apply)
    }

  # aws_db_subnet_group.tfe will be created
  + resource "aws_db_subnet_group" "tfe" {
      + arn                     = (known after apply)
      + description             = "Managed by Terraform"
      + id                      = (known after apply)
      + name                    = (known after apply)
      + name_prefix             = (known after apply)
      + subnet_ids              = (known after apply)
      + supported_network_types = (known after apply)
      + tags                    = (known after apply)
      + tags_all                = (known after apply)
      + vpc_id                  = (known after apply)
    }

  # aws_eip.aws_nat will be created
  + resource "aws_eip" "aws_nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = "vpc"
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags_all             = (known after apply)
      + vpc                  = (known after apply)
    }

  # aws_elasticache_replication_group.redis will be created
  + resource "aws_elasticache_replication_group" "redis" {
      + apply_immediately              = true
      + arn                            = (known after apply)
      + at_rest_encryption_enabled     = true
      + auth_token                     = (sensitive value)
      + auto_minor_version_upgrade     = "true"
      + automatic_failover_enabled     = false
      + cluster_enabled                = (known after apply)
      + configuration_endpoint_address = (known after apply)
      + data_tiering_enabled           = (known after apply)
      + description                    = "Redis replication group for TFE"
      + engine                         = "redis"
      + engine_version                 = "5.0.6"
      + engine_version_actual          = (known after apply)
      + global_replication_group_id    = (known after apply)
      + id                             = (known after apply)
      + maintenance_window             = (known after apply)
      + member_clusters                = (known after apply)
      + multi_az_enabled               = false
      + node_type                      = "cache.t3.medium"
      + num_cache_clusters             = 1
      + num_node_groups                = (known after apply)
      + parameter_group_name           = "default.redis5.0"
      + port                           = 6380
      + primary_endpoint_address       = (known after apply)
      + reader_endpoint_address        = (known after apply)
      + replicas_per_node_group        = (known after apply)
      + replication_group_id           = (known after apply)
      + security_group_ids             = (known after apply)
      + security_group_names           = (known after apply)
      + snapshot_retention_limit       = 0
      + snapshot_window                = (known after apply)
      + subnet_group_name              = (known after apply)
      + tags_all                       = (known after apply)
      + transit_encryption_enabled     = true
    }

  # aws_elasticache_subnet_group.tfe will be created
  + resource "aws_elasticache_subnet_group" "tfe" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = (known after apply)
      + subnet_ids  = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_iam_instance_profile.tfe will be created
  + resource "aws_iam_instance_profile" "tfe" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = (known after apply)
      + path        = "/"
      + role        = (known after apply)
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_role.instance_role will be created
  + resource "aws_iam_role" "instance_role" {
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
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)
    }

  # aws_iam_role_policy.cloudwatch_logs will be created
  + resource "aws_iam_role_policy" "cloudwatch_logs" {
      + id     = (known after apply)
      + name   = (known after apply)
      + policy = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "logs:PutLogEventsBatch",
                          + "logs:PutLogEvents",
                          + "logs:DescribeLogStreams",
                          + "logs:DescribeLogGroups",
                          + "logs:CreateLogStream",
                          + "logs:CreateLogGroup",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:logs:*"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + role   = (known after apply)
    }

  # aws_iam_role_policy.secretsmanager will be created
  + resource "aws_iam_role_policy" "secretsmanager" {
      + id     = (known after apply)
      + name   = (known after apply)
      + policy = (known after apply)
      + role   = (known after apply)
    }

  # aws_iam_role_policy.tfe_asg_discovery will be created
  + resource "aws_iam_role_policy" "tfe_asg_discovery" {
      + id     = (known after apply)
      + name   = (known after apply)
      + policy = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "autoscaling:Describe*"
                      + Effect   = "Allow"
                      + Resource = "*"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + role   = (known after apply)
    }

  # aws_internet_gateway.igw will be created
  + resource "aws_internet_gateway" "igw" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = (known after apply)
      + tags_all = (known after apply)
      + vpc_id   = (known after apply)
    }

  # aws_launch_configuration.tfc_agent will be created
  + resource "aws_launch_configuration" "tfc_agent" {
      + arn                         = (known after apply)
      + associate_public_ip_address = (known after apply)
      + ebs_optimized               = (known after apply)
      + enable_monitoring           = true
      + iam_instance_profile        = (known after apply)
      + id                          = (known after apply)
      + image_id                    = "ami-02e8cc35f1279e103"
      + instance_type               = "t3.medium"
      + key_name                    = "aNAME_HERE2"
      + name                        = (known after apply)
      + name_prefix                 = (known after apply)
      + security_groups             = (known after apply)
      + user_data_base64            = (known after apply)

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = 2
          + http_tokens                 = "optional"
        }

      + root_block_device {
          + delete_on_termination = true
          + encrypted             = (known after apply)
          + iops                  = 1000
          + throughput            = (known after apply)
          + volume_size           = 40
          + volume_type           = "io1"
        }
    }

  # aws_launch_configuration.tfe will be created
  + resource "aws_launch_configuration" "tfe" {
      + arn                         = (known after apply)
      + associate_public_ip_address = (known after apply)
      + ebs_optimized               = (known after apply)
      + enable_monitoring           = true
      + iam_instance_profile        = (known after apply)
      + id                          = (known after apply)
      + image_id                    = "ami-0b3a606764400b644"
      + instance_type               = "t3.2xlarge"
      + key_name                    = "aNAME_HERE2"
      + name                        = (known after apply)
      + name_prefix                 = (known after apply)
      + security_groups             = (known after apply)
      + user_data_base64            = (known after apply)

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = 2
          + http_tokens                 = "optional"
        }

      + root_block_device {
          + delete_on_termination = true
          + encrypted             = (known after apply)
          + iops                  = 1000
          + throughput            = (known after apply)
          + volume_size           = 60
          + volume_type           = "io1"
        }
    }

  # aws_lb.tfe_lb will be created
  + resource "aws_lb" "tfe_lb" {
      + arn                                         = (known after apply)
      + arn_suffix                                  = (known after apply)
      + desync_mitigation_mode                      = "defensive"
      + dns_name                                    = (known after apply)
      + drop_invalid_header_fields                  = false
      + enable_deletion_protection                  = false
      + enable_http2                                = true
      + enable_tls_version_and_cipher_suite_headers = false
      + enable_waf_fail_open                        = false
      + enable_xff_client_port                      = false
      + id                                          = (known after apply)
      + idle_timeout                                = 60
      + internal                                    = (known after apply)
      + ip_address_type                             = (known after apply)
      + load_balancer_type                          = "application"
      + name                                        = (known after apply)
      + preserve_host_header                        = false
      + security_groups                             = (known after apply)
      + subnets                                     = (known after apply)
      + tags_all                                    = (known after apply)
      + vpc_id                                      = (known after apply)
      + xff_header_processing_mode                  = "append"
      + zone_id                                     = (known after apply)
    }

  # aws_lb_listener.lb_443 will be created
  + resource "aws_lb_listener" "lb_443" {
      + arn               = (known after apply)
      + certificate_arn   = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 443
      + protocol          = "HTTPS"
      + ssl_policy        = "ELBSecurityPolicy-2016-08"
      + tags_all          = (known after apply)

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # aws_lb_target_group.tfe_443 will be created
  + resource "aws_lb_target_group" "tfe_443" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + connection_termination             = false
      + deregistration_delay               = "300"
      + id                                 = (known after apply)
      + ip_address_type                    = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancing_algorithm_type      = (known after apply)
      + load_balancing_cross_zone_enabled  = (known after apply)
      + name                               = (known after apply)
      + port                               = 443
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "HTTPS"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 0
      + tags_all                           = (known after apply)
      + target_type                        = "instance"
      + vpc_id                             = (known after apply)

      + health_check {
          + enabled             = true
          + healthy_threshold   = 6
          + interval            = 5
          + matcher             = "200-399"
          + path                = "/_health_check"
          + port                = "traffic-port"
          + protocol            = "HTTPS"
          + timeout             = 2
          + unhealthy_threshold = 2
        }

      + stickiness {
          + cookie_duration = 86400
          + enabled         = true
          + type            = "lb_cookie"
        }
    }

  # aws_nat_gateway.nat will be created
  + resource "aws_nat_gateway" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = (known after apply)
      + tags_all             = (known after apply)
    }

  # aws_route_table.private will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + core_network_arn           = ""
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = (known after apply)
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = (known after apply)
      + tags_all         = (known after apply)
      + vpc_id           = (known after apply)
    }

  # aws_route_table.public will be created
  + resource "aws_route_table" "public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + core_network_arn           = ""
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = (known after apply)
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = ""
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = (known after apply)
      + tags_all         = (known after apply)
      + vpc_id           = (known after apply)
    }

  # aws_route_table_association.private1 will be created
  + resource "aws_route_table_association" "private1" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.private2 will be created
  + resource "aws_route_table_association" "private2" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.public1 will be created
  + resource "aws_route_table_association" "public1" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.public2 will be created
  + resource "aws_route_table_association" "public2" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_s3_bucket.tfe_data will be created
  + resource "aws_s3_bucket" "tfe_data" {
      + acceleration_status         = (known after apply)
      + acl                         = (known after apply)
      + arn                         = (known after apply)
      + bucket                      = (known after apply)
      + bucket_domain_name          = (known after apply)
      + bucket_prefix               = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = true
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + object_lock_enabled         = (known after apply)
      + policy                      = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags_all                    = (known after apply)
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)
    }

  # aws_s3_bucket_policy.tfe_data will be created
  + resource "aws_s3_bucket_policy" "tfe_data" {
      + bucket = (known after apply)
      + id     = (known after apply)
      + policy = (known after apply)
    }

  # aws_s3_bucket_public_access_block.tfe_data will be created
  + resource "aws_s3_bucket_public_access_block" "tfe_data" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # aws_s3_bucket_versioning.tfe_data will be created
  + resource "aws_s3_bucket_versioning" "tfe_data" {
      + bucket = (known after apply)
      + id     = (known after apply)

      + versioning_configuration {
          + mfa_delete = (known after apply)
          + status     = "Enabled"
        }
    }

  # aws_secretsmanager_secret.agent_token will be created
  + resource "aws_secretsmanager_secret" "agent_token" {
      + arn                            = (known after apply)
      + description                    = "TFC agent token"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 0
      + tags_all                       = (known after apply)
    }

  # aws_secretsmanager_secret.tfe_license will be created
  + resource "aws_secretsmanager_secret" "tfe_license" {
      + arn                            = (known after apply)
      + description                    = "The TFE license"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 0
      + tags_all                       = (known after apply)
    }

  # aws_secretsmanager_secret.tls_certificate will be created
  + resource "aws_secretsmanager_secret" "tls_certificate" {
      + arn                            = (known after apply)
      + description                    = "TLS certificate"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 0
      + tags_all                       = (known after apply)
    }

  # aws_secretsmanager_secret.tls_chain will be created
  + resource "aws_secretsmanager_secret" "tls_chain" {
      + arn                            = (known after apply)
      + description                    = "TLS chain"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 0
      + tags_all                       = (known after apply)
    }

  # aws_secretsmanager_secret.tls_key will be created
  + resource "aws_secretsmanager_secret" "tls_key" {
      + arn                            = (known after apply)
      + description                    = "TLS key"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 0
      + tags_all                       = (known after apply)
    }

  # aws_secretsmanager_secret_version.agent_token will be created
  + resource "aws_secretsmanager_secret_version" "agent_token" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_id      = (known after apply)
      + secret_string  = (sensitive value)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.tfe_license will be created
  + resource "aws_secretsmanager_secret_version" "tfe_license" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.tls_certificate will be created
  + resource "aws_secretsmanager_secret_version" "tls_certificate" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.tls_chain will be created
  + resource "aws_secretsmanager_secret_version" "tls_chain" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.tls_key will be created
  + resource "aws_secretsmanager_secret_version" "tls_key" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_security_group.internal_sg will be created
  + resource "aws_security_group" "internal_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow outgoing connections"
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow all the icmp types"
              + from_port        = -1
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "icmp"
              + security_groups  = []
              + self             = false
              + to_port          = -1
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow netdata port"
              + from_port        = 19999
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 19999
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow ssh port 22"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = "Allow netdata port from public security group"
              + from_port        = 19999
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 19999
            },
          + {
              + cidr_blocks      = []
              + description      = "Allow ssh port 22 from public security group"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = []
              + description      = "allow Vault HA request forwarding"
              + from_port        = 8201
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 8201
            },
          + {
              + cidr_blocks      = []
              + description      = "allow https port incoming connection from Load balancer"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = "allow postgres port incoming connections"
              + from_port        = 5432
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 5432
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.lb_sg will be created
  + resource "aws_security_group" "lb_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow outgoing connections"
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow netdata port incoming connection"
              + from_port        = 19999
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 19999
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow ssh port incoming connection"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.public_sg will be created
  + resource "aws_security_group" "public_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow outgoing connections"
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow http port incoming connection"
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow netdata port 19999"
              + from_port        = 19999
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 19999
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow ssh port 22"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.redis_sg will be created
  + resource "aws_security_group" "redis_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 6379
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 6380
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_subnet.subnet_private1 will be created
  + resource "aws_subnet" "subnet_private1" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-north-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.1.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_private2 will be created
  + resource "aws_subnet" "subnet_private2" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-north-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.2.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_public1 will be created
  + resource "aws_subnet" "subnet_public1" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-north-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.3.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_public2 will be created
  + resource "aws_subnet" "subnet_public2" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-north-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.4.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_vpc.vpc will be created
  + resource "aws_vpc" "vpc" {
      + arn                                  = (known after apply)
      + cidr_block                           = "10.5.0.0/16"
      + default_network_acl_id               = (known after apply)
      + default_route_table_id               = (known after apply)
      + default_security_group_id            = (known after apply)
      + dhcp_options_id                      = (known after apply)
      + enable_dns_hostnames                 = true
      + enable_dns_support                   = true
      + enable_network_address_usage_metrics = (known after apply)
      + id                                   = (known after apply)
      + instance_tenancy                     = "default"
      + ipv6_association_id                  = (known after apply)
      + ipv6_cidr_block                      = (known after apply)
      + ipv6_cidr_block_network_border_group = (known after apply)
      + main_route_table_id                  = (known after apply)
      + owner_id                             = (known after apply)
      + tags                                 = (known after apply)
      + tags_all                             = (known after apply)
    }

  # aws_vpc_endpoint.s3 will be created
  + resource "aws_vpc_endpoint" "s3" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + ip_address_type       = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = false
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-north-1.s3"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags_all              = (known after apply)
      + vpc_endpoint_type     = "Gateway"
      + vpc_id                = (known after apply)
    }

  # aws_vpc_endpoint_route_table_association.private_s3_endpoint will be created
  + resource "aws_vpc_endpoint_route_table_association" "private_s3_endpoint" {
      + id              = (known after apply)
      + route_table_id  = (known after apply)
      + vpc_endpoint_id = (known after apply)
    }

  # cloudflare_record.tfe will be created
  + resource "cloudflare_record" "tfe" {
      + allow_overwrite = false
      + created_on      = (known after apply)
      + hostname        = (known after apply)
      + id              = (known after apply)
      + metadata        = (known after apply)
      + modified_on     = (known after apply)
      + name            = (known after apply)
      + proxiable       = (known after apply)
      + ttl             = 1
      + type            = "CNAME"
      + value           = (known after apply)
      + zone_id         = (sensitive value)
    }

  # random_id.enc_password will be created
  + resource "random_id" "enc_password" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.install_id will be created
  + resource "random_id" "install_id" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.redis_password will be created
  + resource "random_id" "redis_password" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.user_token will be created
  + resource "random_id" "user_token" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_string.friendly_name will be created
  + resource "random_string" "friendly_name" {
      + id          = (known after apply)
      + length      = 4
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = false
      + numeric     = false
      + result      = (known after apply)
      + special     = false
      + upper       = false
    }

  # random_string.password will be created
  + resource "random_string" "password" {
      + id          = (known after apply)
      + length      = 16
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

  # random_string.pgsql_password will be created
  + resource "random_string" "pgsql_password" {
      + id          = (known after apply)
      + length      = 24
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

Plan: 59 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + aws_active_agents_ips          = (known after apply)
  + aws_agent_ec2_ids              = (known after apply)
  + aws_lb_active_target_group_ips = (known after apply)
  + aws_tfe_ec2_ids                = (known after apply)
  + friendly_name_prefix           = (known after apply)
  + internal_sg_id                 = (known after apply)
  + region                         = "eu-north-1"
  + ssh_key_name                   = "aNAME_HERE2"
  + subnet_private1_id             = (known after apply)
  + subnet_private2_id             = (known after apply)
  + subnet_public1_id              = (known after apply)
  + subnet_public2_id              = (known after apply)
  + tfe_hostname                   = (known after apply)
  + url                            = (known after apply)
  + vpc_id                         = (known after apply)
random_id.install_id: Creating...
random_id.enc_password: Creating...
random_id.redis_password: Creating...
random_id.user_token: Creating...
random_id.redis_password: Creation complete after 0s [id=geaPfHCNzzWnYJW5muwNsA]
random_id.enc_password: Creation complete after 0s [id=sAFcNmFKfiv00oUAJ4qenA]
random_id.user_token: Creation complete after 0s [id=TIm-RIxQsDktoYJITU40Jw]
random_string.pgsql_password: Creating...
random_string.password: Creating...
random_string.friendly_name: Creating...
random_id.install_id: Creation complete after 0s [id=jLLVMkr2F_BuO1as0UX99g]
random_string.pgsql_password: Creation complete after 1s [id=HaXOn9xAdoYGoSVfxaFTsGoR]
random_string.friendly_name: Creation complete after 1s [id=vveo]
random_string.password: Creation complete after 1s [id=YhKE9ywMgHoHEwMW]
aws_secretsmanager_secret.agent_token: Creating...
aws_secretsmanager_secret.tfe_license: Creating...
aws_secretsmanager_secret.tls_key: Creating...
aws_secretsmanager_secret.tls_chain: Creating...
aws_secretsmanager_secret.tls_certificate: Creating...
aws_vpc.vpc: Creating...
aws_iam_role.instance_role: Creating...
aws_acm_certificate.tfe: Creating...
aws_s3_bucket.tfe_data: Creating...
aws_secretsmanager_secret.agent_token: Creation complete after 1s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-agent_token-AuV2gn]
aws_secretsmanager_secret.tfe_license: Creation complete after 1s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-tfe_license-taIvxc]
aws_secretsmanager_secret.tls_key: Creation complete after 1s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-tfe_key-p7pEha]
aws_secretsmanager_secret_version.agent_token: Creating...
aws_secretsmanager_secret.tls_chain: Creation complete after 1s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-tfe_chain-WmQ98i]
aws_secretsmanager_secret.tls_certificate: Creation complete after 1s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-tfe_certificate-taIvxc]
aws_secretsmanager_secret_version.tfe_license: Creating...
aws_secretsmanager_secret_version.tls_key: Creating...
aws_secretsmanager_secret_version.tls_certificate: Creating...
aws_secretsmanager_secret_version.tls_chain: Creating...
aws_secretsmanager_secret_version.agent_token: Creation complete after 0s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-agent_token-AuV2gn|6B8BF4C2-F6A5-4FE7-AB9D-6442B79F3510]
aws_secretsmanager_secret_version.tfe_license: Creation complete after 0s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-tfe_license-taIvxc|6726F6A5-3C01-4CDB-B340-AE5757ED946D]
aws_secretsmanager_secret_version.tls_key: Creation complete after 0s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-tfe_key-p7pEha|D4D8E793-B84F-4F95-93E5-F329A16968B1]
aws_secretsmanager_secret_version.tls_certificate: Creation complete after 0s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-tfe_certificate-taIvxc|B41721F2-A4A8-44B1-B294-9FEB738F1F39]
aws_secretsmanager_secret_version.tls_chain: Creation complete after 0s [id=arn:aws:secretsmanager:eu-north-1:247711370364:secret:aNAME_HERE-vveo-tfe_chain-WmQ98i|621A5C32-E157-429F-B7AB-3942DDFBC00C]
data.aws_iam_policy_document.secretsmanager: Reading...
data.aws_iam_policy_document.secretsmanager: Read complete after 0s [id=2387901931]
aws_acm_certificate.tfe: Creation complete after 1s [id=arn:aws:acm:eu-north-1:247711370364:certificate/83f8917e-eb1b-4eb3-bbad-1b63d7c5babc]
aws_iam_role.instance_role: Creation complete after 2s [id=aNAME_HERE-vveo-tfe20230728103239194600000001]
aws_iam_role_policy.secretsmanager: Creating...
aws_iam_role_policy.tfe_asg_discovery: Creating...
aws_iam_role_policy.cloudwatch_logs: Creating...
aws_iam_instance_profile.tfe: Creating...
aws_iam_role_policy.tfe_asg_discovery: Creation complete after 0s [id=aNAME_HERE-vveo-tfe20230728103239194600000001:aNAME_HERE-vveo-tfe-asg-discovery]
aws_iam_role_policy.cloudwatch_logs: Creation complete after 0s [id=aNAME_HERE-vveo-tfe20230728103239194600000001:aNAME_HERE-vveo-tfe-cloudwatch]
aws_iam_role_policy.secretsmanager: Creation complete after 0s [id=aNAME_HERE-vveo-tfe20230728103239194600000001:aNAME_HERE-vveo-tfe-secretsmanager]
aws_s3_bucket.tfe_data: Creation complete after 2s [id=aNAME_HERE-vveo-tfe-data]
aws_s3_bucket_public_access_block.tfe_data: Creating...
data.aws_iam_policy_document.tfe_data: Reading...
aws_s3_bucket_versioning.tfe_data: Creating...
data.aws_iam_policy_document.tfe_data: Read complete after 0s [id=493257632]
aws_iam_instance_profile.tfe: Creation complete after 1s [id=aNAME_HERE-vveo-tfe20230728103240571000000002]
aws_s3_bucket_public_access_block.tfe_data: Creation complete after 1s [id=aNAME_HERE-vveo-tfe-data]
aws_s3_bucket_policy.tfe_data: Creating...
aws_s3_bucket_versioning.tfe_data: Creation complete after 2s [id=aNAME_HERE-vveo-tfe-data]
aws_vpc.vpc: Still creating... [10s elapsed]
aws_vpc.vpc: Creation complete after 12s [id=vpc-0acd077e9a1d3dbdc]
aws_internet_gateway.igw: Creating...
aws_subnet.subnet_public2: Creating...
aws_subnet.subnet_private1: Creating...
aws_subnet.subnet_public1: Creating...
aws_subnet.subnet_private2: Creating...
aws_vpc_endpoint.s3: Creating...
aws_lb_target_group.tfe_443: Creating...
aws_security_group.lb_sg: Creating...
aws_security_group.public_sg: Creating...
aws_internet_gateway.igw: Creation complete after 1s [id=igw-0688cec1f733f6469]
aws_eip.aws_nat: Creating...
aws_subnet.subnet_public2: Creation complete after 1s [id=subnet-03d01fc643e3beca8]
aws_route_table.public: Creating...
aws_subnet.subnet_public1: Creation complete after 1s [id=subnet-0acf4851f10350c5b]
aws_subnet.subnet_private1: Creation complete after 1s [id=subnet-0ca14468a2ff2ee4a]
aws_subnet.subnet_private2: Creation complete after 1s [id=subnet-0d5d04570213666a6]
aws_elasticache_subnet_group.tfe: Creating...
aws_db_subnet_group.tfe: Creating...
aws_s3_bucket_policy.tfe_data: Still creating... [10s elapsed]
aws_lb_target_group.tfe_443: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:targetgroup/aNAME_HERE-vveo-tfe-tg-443/ebf0f520b69c3ff3]
aws_eip.aws_nat: Creation complete after 0s [id=eipalloc-040a6ae7aa007de97]
aws_nat_gateway.nat: Creating...
aws_route_table.public: Creation complete after 1s [id=rtb-0fea577586f7c5927]
aws_route_table_association.public2: Creating...
aws_route_table_association.public1: Creating...
aws_route_table_association.public2: Creation complete after 0s [id=rtbassoc-019d6f8f7798fdc9b]
aws_route_table_association.public1: Creation complete after 0s [id=rtbassoc-029c5b47b30f49d08]
aws_security_group.public_sg: Creation complete after 3s [id=sg-068147e6130995ead]
aws_security_group.lb_sg: Creation complete after 3s [id=sg-0a4d6181678b3182f]
aws_db_subnet_group.tfe: Creation complete after 2s [id=aNAME_HERE-vveo-db-subnet]
aws_lb.tfe_lb: Creating...
aws_security_group.internal_sg: Creating...
aws_elasticache_subnet_group.tfe: Creation complete after 2s [id=aNAME_HERE-vveo-tfe-redis]
aws_security_group.internal_sg: Creation complete after 2s [id=sg-07e43dbf48d4527d8]
data.aws_instances.tfe: Reading...
data.aws_instances.tfc_agent: Reading...
aws_launch_configuration.tfc_agent: Creating...
aws_security_group.redis_sg: Creating...
aws_db_instance.tfe: Creating...
data.aws_instances.tfe: Read complete after 0s [id=eu-north-1]
data.aws_instances.tfc_agent: Read complete after 0s [id=eu-north-1]
aws_launch_configuration.tfc_agent: Creation complete after 1s [id=aNAME_HERE-vveo-tfc_agent-launch-configuration20230728103256215200000005]
aws_autoscaling_group.tfc_agent: Creating...
aws_vpc_endpoint.s3: Creation complete after 6s [id=vpce-0b52366119f60cdd1]
aws_security_group.redis_sg: Creation complete after 2s [id=sg-071ece737762be401]
aws_elasticache_replication_group.redis: Creating...
aws_s3_bucket_policy.tfe_data: Creation complete after 16s [id=aNAME_HERE-vveo-tfe-data]
aws_nat_gateway.nat: Still creating... [10s elapsed]
aws_lb.tfe_lb: Still creating... [10s elapsed]
aws_db_instance.tfe: Still creating... [10s elapsed]
aws_autoscaling_group.tfc_agent: Still creating... [10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [10s elapsed]
aws_autoscaling_group.tfc_agent: Creation complete after 15s [id=aNAME_HERE-vveo-asg-tfc_agent]
aws_nat_gateway.nat: Still creating... [20s elapsed]
aws_lb.tfe_lb: Still creating... [20s elapsed]
aws_db_instance.tfe: Still creating... [20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [20s elapsed]
aws_nat_gateway.nat: Still creating... [30s elapsed]
aws_lb.tfe_lb: Still creating... [30s elapsed]
aws_db_instance.tfe: Still creating... [30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [30s elapsed]
aws_nat_gateway.nat: Still creating... [40s elapsed]
aws_lb.tfe_lb: Still creating... [40s elapsed]
aws_db_instance.tfe: Still creating... [40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [40s elapsed]
aws_nat_gateway.nat: Still creating... [50s elapsed]
aws_lb.tfe_lb: Still creating... [50s elapsed]
aws_db_instance.tfe: Still creating... [50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [50s elapsed]
aws_nat_gateway.nat: Still creating... [1m0s elapsed]
aws_lb.tfe_lb: Still creating... [1m0s elapsed]
aws_db_instance.tfe: Still creating... [1m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m0s elapsed]
aws_nat_gateway.nat: Still creating... [1m10s elapsed]
aws_lb.tfe_lb: Still creating... [1m10s elapsed]
aws_db_instance.tfe: Still creating... [1m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m10s elapsed]
aws_nat_gateway.nat: Still creating... [1m20s elapsed]
aws_lb.tfe_lb: Still creating... [1m20s elapsed]
aws_db_instance.tfe: Still creating... [1m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m20s elapsed]
aws_nat_gateway.nat: Still creating... [1m30s elapsed]
aws_lb.tfe_lb: Still creating... [1m30s elapsed]
aws_db_instance.tfe: Still creating... [1m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m30s elapsed]
aws_nat_gateway.nat: Still creating... [1m40s elapsed]
aws_lb.tfe_lb: Still creating... [1m40s elapsed]
aws_db_instance.tfe: Still creating... [1m40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m40s elapsed]
aws_nat_gateway.nat: Still creating... [1m50s elapsed]
aws_lb.tfe_lb: Still creating... [1m50s elapsed]
aws_db_instance.tfe: Still creating... [1m50s elapsed]
aws_nat_gateway.nat: Creation complete after 1m55s [id=nat-071e59b1460ce92fe]
aws_route_table.private: Creating...
aws_route_table.private: Creation complete after 1s [id=rtb-05be18e5712f2d026]
aws_vpc_endpoint_route_table_association.private_s3_endpoint: Creating...
aws_route_table_association.private2: Creating...
aws_route_table_association.private1: Creating...
aws_elasticache_replication_group.redis: Still creating... [1m50s elapsed]
aws_route_table_association.private2: Creation complete after 1s [id=rtbassoc-09835d11c12ebe5d0]
aws_route_table_association.private1: Creation complete after 1s [id=rtbassoc-034f57b2388300749]
aws_vpc_endpoint_route_table_association.private_s3_endpoint: Creation complete after 1s [id=a-vpce-0b52366119f60cdd124366424]
aws_lb.tfe_lb: Still creating... [2m0s elapsed]
aws_db_instance.tfe: Still creating... [2m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m0s elapsed]
aws_lb.tfe_lb: Still creating... [2m10s elapsed]
aws_db_instance.tfe: Still creating... [2m10s elapsed]
aws_lb.tfe_lb: Creation complete after 2m12s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:loadbalancer/app/aNAME_HERE-vveo-tfe-app-lb/f7c0241762d15223]
cloudflare_record.tfe: Creating...
aws_lb_listener.lb_443: Creating...
aws_lb_listener.lb_443: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-north-1:247711370364:listener/app/aNAME_HERE-vveo-tfe-app-lb/f7c0241762d15223/8a8a482d9b0d0154]
aws_elasticache_replication_group.redis: Still creating... [2m10s elapsed]
cloudflare_record.tfe: Creation complete after 5s [id=3b028ebe6f2df4572f55c225d1e42738]
aws_db_instance.tfe: Still creating... [2m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m20s elapsed]
aws_db_instance.tfe: Still creating... [2m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m30s elapsed]
aws_db_instance.tfe: Still creating... [2m40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m40s elapsed]
aws_db_instance.tfe: Still creating... [2m50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m50s elapsed]
aws_db_instance.tfe: Still creating... [3m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m0s elapsed]
aws_db_instance.tfe: Still creating... [3m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m10s elapsed]
aws_db_instance.tfe: Still creating... [3m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m20s elapsed]
aws_db_instance.tfe: Creation complete after 3m27s [id=db-GPPUNJFVR64L373A5PIGPWC3T4]
aws_elasticache_replication_group.redis: Still creating... [9m10s elapsed]
aws_elasticache_replication_group.redis: Creation complete after 9m15s [id=aNAME_HERE-vveo-tfe]
aws_launch_configuration.tfe: Creating...
aws_launch_configuration.tfe: Creation complete after 1s [id=aNAME_HERE-vveo-tfe-launch-configuration20230728104213094600000007]
aws_autoscaling_group.tfe: Creating...
aws_autoscaling_group.tfe: Still creating... [10s elapsed]
aws_autoscaling_group.tfe: Creation complete after 16s [id=aNAME_HERE-vveo-tfe-asg]

Apply complete! Resources: 59 added, 0 changed, 0 destroyed.

Outputs:

aws_active_agents_ips = ""
aws_agent_ec2_ids = toset([])
aws_lb_active_target_group_ips = ""
aws_tfe_ec2_ids = toset([])
friendly_name_prefix = "aNAME_HERE-vveo"
internal_sg_id = "sg-07e43dbf48d4527d8"
region = "eu-north-1"
ssh_key_name = "aNAME_HERE2"
subnet_private1_id = "subnet-0ca14468a2ff2ee4a"
subnet_private2_id = "subnet-0d5d04570213666a6"
subnet_public1_id = "subnet-0acf4851f10350c5b"
subnet_public2_id = "subnet-03d01fc643e3beca8"
tfe_hostname = "vveotfe.NAME_HERE.cc"
url = "https://vveotfe.NAME_HERE.cc/admin/account/new?token=2658746587fdjkjhbsgsjfhsbg37b"
vpc_id = "vpc-0acd077e9a1d3dbdc"
```
