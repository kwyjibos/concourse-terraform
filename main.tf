# Specify the provider and access details
provider "aws" {
  region = "${var.aws_region}"
}

terraform {
  required_version = "> 0.10.0"
  backend "s3" {
    key     = "terraform.tfstate"
    encrypt = true
    bucket  = "concourse-aws-terraform"
    region  = "eu-west-1"
  }
}


# Create an IAM role for Concourse workers, allow S3 access - https://github.com/concourse/s3-resource
resource "aws_iam_role" "worker_iam_role" {
  name = "worker_iam_role"
  path = "/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {"AWS": "*"},
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "worker_iam_instance_profile" {
  name = "worker_iam_instance_profile"
  role = "${aws_iam_role.worker_iam_role.name}"
}
#
# resource "aws_iam_policy_attachment" "iam-ecr-policy-attach" {
#   name = "ecr-policy-attachment"
#   roles = ["${aws_iam_role.worker_iam_role.name}"]
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
# }

# resource "aws_iam_policy_attachment" "iam-s3-policy-attach" {
#   name = "ecr-policy-attachment"
#   roles = ["${aws_iam_role.worker_iam_role.name}"]
#   policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
# }

resource "aws_iam_role_policy_attachment" "iam-s3-policy-attach" {
    role       = "${aws_iam_role.worker_iam_role.name}"
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_elb" "web-elb" {
  name = "${var.prefix}-concourse"
  security_groups = ["${aws_security_group.external_lb.id}"]
  subnets = ["${split(",", var.pub_subnet_id)}"]
  cross_zone_load_balancing = "true"

  listener {
    instance_port = "${var.elb_listener_instance_port}"
    instance_protocol = "tcp"
    lb_port = "${var.elb_listener_lb_port}"
    lb_protocol = "${var.elb_listener_lb_port == 80 ? "tcp" : "ssl"}"
    ssl_certificate_id = "${data.aws_ssm_parameter.ssl_certificate_arn.value}"
  }

  listener {
    instance_port = "${var.tsa_port}"
    instance_protocol = "tcp"
    lb_port = "${var.tsa_port}"
    lb_protocol = "tcp"
  }

  health_check {
    healthy_threshold = 2
    unhealthy_threshold = 2
    timeout = 3
    target = "TCP:${var.elb_listener_instance_port}"
    interval = 5
  }
}

resource "aws_autoscaling_group" "web-asg" {
  # See "Phasing in" an Autoscaling Group? https://groups.google.com/forum/#!msg/terraform-tool/7Gdhv1OAc80/iNQ93riiLwAJ
  # * Recreation of the launch configuration triggers recreation of this ASG and its EC2 instances
  # * Modification to the lc (change to referring AMI) triggers recreation of this ASG
  name = "${var.prefix}-${aws_launch_configuration.web-lc.name}-${var.ami}"
  availability_zones = ["${split(",", var.availability_zones)}"]
  max_size = "${var.asg_max}"
  min_size = "${var.asg_min}"
  desired_capacity = "${var.web_asg_desired}"
  launch_configuration = "${aws_launch_configuration.web-lc.name}"
  load_balancers = ["${aws_elb.web-elb.name}"]
  vpc_zone_identifier = ["${split(",", var.priv_subnet_id)}"]

  tag {
    key = "Name"
    value = "${var.prefix}-concourse-web"
    propagate_at_launch = "true"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "worker-asg" {
  name = "${var.prefix}-${aws_launch_configuration.worker-lc.name}-${var.ami}"
  availability_zones = ["${split(",", var.availability_zones)}"]
  max_size = "${var.asg_max}"
  min_size = "${var.asg_min}"
  desired_capacity = "${var.worker_asg_desired}"
  launch_configuration = "${aws_launch_configuration.worker-lc.name}"
  vpc_zone_identifier = ["${split(",", var.priv_subnet_id)}"]

  tag {
    key = "Name"
    value = "${var.prefix}-concourse-worker"
    propagate_at_launch = "true"
  }
}

resource "aws_autoscaling_group" "windows-worker-asg" {
  name = "${var.prefix}-${aws_launch_configuration.windows-worker-lc.name}-${data.aws_ami.amazon_windows_2016.image_id}"
  availability_zones = ["${split(",", var.availability_zones)}"]
  max_size = "${var.windows_asg_max}"
  min_size = "${var.windows_asg_min}"
  desired_capacity = "${var.windows_worker_asg_desired}"
  launch_configuration = "${aws_launch_configuration.windows-worker-lc.name}"
  vpc_zone_identifier = ["${split(",", var.priv_subnet_id)}"]

  tag {
    key = "Name"
    value = "${var.prefix}-concourse-windows-worker"
    propagate_at_launch = "true"
  }
}

resource "aws_launch_configuration" "web-lc" {
  name_prefix = "${var.prefix}-concourse-web-"
  image_id = "${var.ami}"
  instance_type = "${var.web_instance_type}"
  spot_price = "${substr(var.web_instance_type, 0, 2) == "t2" ? "" : var.web_spot_price}"
  security_groups = ["${aws_security_group.concourse.id}","${aws_security_group.atc.id}","${aws_security_group.tsa.id}"]
  user_data = "${data.template_cloudinit_config.web.rendered}"
  key_name = "${var.key_name}"

  root_block_device {
    volume_type = "gp2"
  }


  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_launch_configuration" "worker-lc" {
  name_prefix = "${var.prefix}-concourse-worker-"
  image_id = "${var.ami}"
  instance_type = "${var.worker_instance_type}"
  spot_price = "${substr(var.worker_instance_type, 0, 2) == "t2" ? "" : var.worker_spot_price}"
  security_groups = ["${aws_security_group.concourse.id}", "${aws_security_group.worker.id}"]
  user_data = "${data.template_cloudinit_config.worker.rendered}"
  key_name = "${var.key_name}"
  iam_instance_profile = "${var.worker_instance_profile != "" ? var.worker_instance_profile : aws_iam_instance_profile.worker_iam_instance_profile.id}"

  lifecycle {
    create_before_destroy = true
  }

  ephemeral_block_device {
    device_name = "/dev/xvdb"
    virtual_name = "ephemeral0"
  }

  enable_monitoring = "true"
  ebs_optimized = "true"
}

# Lookup the correct AMI based on the region specified
data "aws_ami" "amazon_windows_2016" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2016-English-Full-Base-*"]
  }
}

resource "aws_launch_configuration" "windows-worker-lc" {
  name_prefix = "${var.prefix}-concourse-windows-worker-"
  # image_id = "ami-9d5167e4"
  image_id = "ami-049bf5e5ea4af0cfe"
  instance_type = "${var.windows_worker_instance_type}"
  spot_price = "${substr(var.windows_worker_spot_price, 0, 2) == "t2" ? "" : var.windows_worker_spot_price}"
  security_groups = ["${aws_security_group.concourse.id}", "${aws_security_group.worker.id}"]

  user_data = <<EOF
<powershell>
  Start-Sleep -s 10
  Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

  $concourseDirExists = Test-Path -Path "C:\Concourse"

  if ($concourseDirExists -eq $false) { mkdir C:\concourse }

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  $concourseExeExists = Test-Path -Path "C:\concourse\concourse_windows_amd64.exe" -PathType leaf

  if ($concourseExeExists -eq $false) {
    Invoke-WebRequest 'https://github.com/concourse/concourse/releases/download/v3.14.1/concourse_windows_amd64.exe' -UseBasicParsing -OutFile C:\concourse\concourse_windows_amd64.exe
  }

  $instance_id = (Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/instance-id -UseBasicParsing).content
  $peer_ip = (Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/local-ipv4 -UseBasicParsing).content

  "${data.aws_ssm_parameter.tsa_public_key.value}" | Out-File -encoding ascii C:\concourse\tsa-public-key.pub -NoNewline
  "${data.aws_ssm_parameter.tsa_worker_private_key.value}" | Out-File -encoding ascii C:\concourse\tsa-worker-private-key -NoNewline

  Start-Process -FilePath C:\concourse\concourse_windows_amd64.exe -RedirectStandardOutput "C:\concourse\stdout.txt" -RedirectStandardError "C:\concourse\stderr.txt" -WindowStyle Hidden -ArgumentList ("worker /name $instance_id /peer-ip $peer_ip /bind-ip $peer_ip /baggageclaim-bind-ip 0.0.0.0 /work-dir C:\concourse\containers /tsa-worker-private-key C:\concourse\tsa-worker-private-key /tsa-public-key C:\concourse\tsa-public-key.pub /tsa-host ${aws_elb.web-elb.dns_name}:${var.tsa_port}")
</powershell>
<persist>true</persist>
EOF

  key_name = "${var.key_name}"
  iam_instance_profile = "${var.worker_instance_profile != "" ? var.worker_instance_profile : aws_iam_instance_profile.worker_iam_instance_profile.id}"

  root_block_device {
    volume_type = "gp2"
    volume_size = "120"
  }

  lifecycle {
    create_before_destroy = true
  }

  enable_monitoring = "true"
  ebs_optimized = "true"
}

# Retrieve sensitive values from SSM
data "aws_ssm_parameter" "db_username" {
  name  = "db_username"
}

data "aws_ssm_parameter" "db_password" {
  name  = "db_password"
}

data "aws_ssm_parameter" "github_auth_client_id" {
  name  = "github_auth_client_id"
}

data "aws_ssm_parameter" "github_auth_client_secret" {
  name  = "github_auth_client_secret"
}

data "aws_ssm_parameter" "in_access_allowed_cidrs" {
  name  = "in_access_allowed_cidrs"
}

data "aws_ssm_parameter" "session_signing_key" {
  name  = "session_signing_key"
}

data "aws_ssm_parameter" "ssl_certificate_arn" {
  name  = "ssl_certificate_arn"
}

data "aws_ssm_parameter" "tsa_authorized_keys" {
  name  = "tsa_authorized_keys"
}

data "aws_ssm_parameter" "tsa_host_key" {
  name  = "tsa_host_key"
}

data "aws_ssm_parameter" "tsa_public_key" {
  name  = "tsa_public_key"
}

data "aws_ssm_parameter" "tsa_worker_private_key" {
  name  = "tsa_worker_private_key"
}

data "aws_ssm_parameter" "vault_url" {
  name  = "vault_url"
}

data "aws_ssm_parameter" "vault_client_token" {
  name  = "vault_client_token"
}

data "template_file" "install_concourse" {
  template = "${file("${path.module}/00_install_concourse.sh.tpl")}"
}

data "template_file" "start_concourse_web" {
  template = "${file("${path.module}/01_start_concourse_web.sh.tpl")}"

  vars {
    session_signing_key = "${data.aws_ssm_parameter.session_signing_key.value}"
    tsa_host_key = "${data.aws_ssm_parameter.tsa_host_key.value}"
    tsa_authorized_keys = "${data.aws_ssm_parameter.tsa_authorized_keys.value}"
    postgres_data_source = "postgres://${data.aws_ssm_parameter.db_username.value}:${data.aws_ssm_parameter.db_password.value}@${aws_db_instance.concourse.endpoint}/concourse"
    external_url = "${var.elb_listener_lb_protocol}://${element(split(",","${aws_elb.web-elb.dns_name},${var.custom_external_domain_name}"), var.use_custom_external_domain_name)}${element(split(",",",:${var.elb_listener_lb_port}"), var.use_custom_elb_port)}"
    basic_auth_username = "${var.basic_auth_username}"
    basic_auth_password = "${var.basic_auth_password}"
    github_auth_client_id = "${data.aws_ssm_parameter.github_auth_client_id.value}"
    github_auth_client_secret = "${data.aws_ssm_parameter.github_auth_client_secret.value}"
    github_auth_organizations = "${var.github_auth_organizations}"
    github_auth_teams = "${var.github_auth_teams}"
    github_auth_users = "${var.github_auth_users}"
    vault_url = "${data.aws_ssm_parameter.vault_url.value}"
    vault_ca_cert = "${var.vault_ca_cert}"
    vault_client_token = "${data.aws_ssm_parameter.vault_client_token.value}"
  }
}

data "template_file" "start_concourse_worker" {
  template = "${file("${path.module}/02_start_concourse_worker.sh.tpl")}"

  vars {
    tsa_host = "${aws_elb.web-elb.dns_name}"
    tsa_port = "${var.tsa_port}"
    tsa_public_key = "${data.aws_ssm_parameter.tsa_public_key.value}"
    tsa_worker_private_key = "${data.aws_ssm_parameter.tsa_worker_private_key.value}"
  }
}

data "template_cloudinit_config" "web" {
  # Make both turned off until https://github.com/hashicorp/terraform/issues/4794 is fixed
  gzip          = false
  base64_encode = false

  part {
    content_type = "text/x-shellscript"
    content      = "${data.template_file.install_concourse.rendered}"
  }

  part {
    content_type = "text/x-shellscript"
    content      = "${data.template_file.start_concourse_web.rendered}"
  }
}

data "template_cloudinit_config" "worker" {
  # Make both turned off until https://github.com/hashicorp/terraform/issues/4794 is fixed
  gzip          = false
  base64_encode = false

  part {
    content_type = "text/x-shellscript"
    content      = "${data.template_file.install_concourse.rendered}"
  }

  part {
    content_type = "text/x-shellscript"
    content      = "${data.template_file.start_concourse_worker.rendered}"
  }
}

resource "aws_security_group" "concourse" {
  name_prefix = "${var.prefix}-concourse"
  vpc_id = "${var.vpc_id}"

  # SSH access from a specific CIDRS
  # ingress {
  #   from_port = 22
  #   to_port = 22
  #   protocol = "tcp"
  #   cidr_blocks = [ "${split(",", data.aws_ssm_parameter.in_access_allowed_cidrs.value)}" ]
  # }
  #
  # ingress {
  #   from_port = 3389
  #   to_port = 3389
  #   protocol = "tcp"
  #   cidr_blocks = [ "${split(",", data.aws_ssm_parameter.in_access_allowed_cidrs.value)}" ]
  # }

  # outbound internet access
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "atc" {
  name_prefix = "${var.prefix}-concourse-atc"
  vpc_id = "${var.vpc_id}"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_external_lb_to_atc_access" {
  type = "ingress"
  from_port = "${var.elb_listener_instance_port}"
  to_port = "${var.elb_listener_instance_port}"
  protocol = "tcp"

  security_group_id = "${aws_security_group.tsa.id}"
  source_security_group_id = "${aws_security_group.external_lb.id}"
}

resource "aws_security_group_rule" "allow_atc_to_worker_access" {
  type = "ingress"
  from_port = "0"
  to_port = "65535"
  protocol = "tcp"

  security_group_id = "${aws_security_group.worker.id}"
  source_security_group_id = "${aws_security_group.atc.id}"
}

resource "aws_security_group" "tsa" {
  name_prefix = "${var.prefix}-concourse-tsa"
  vpc_id = "${var.vpc_id}"

  # outbound internet access
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_worker_to_tsa_access" {
  type = "ingress"
  from_port = 2222
  to_port = 2222
  protocol = "tcp"

  security_group_id = "${aws_security_group.external_lb.id}"
  source_security_group_id = "${aws_security_group.worker.id}"
}

resource "aws_security_group_rule" "allow_external_lb_to_tsa_access" {
  type = "ingress"
  from_port = 2222
  to_port = 2222
  protocol = "tcp"

  security_group_id = "${aws_security_group.tsa.id}"
  source_security_group_id = "${aws_security_group.external_lb.id}"
}

resource "aws_security_group" "worker" {
  name_prefix = "${var.prefix}-concourse-worker"
  vpc_id = "${var.vpc_id}"

  # outbound internet access
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "external_lb" {
  name_prefix = "${var.prefix}-concourse-lb"

  vpc_id = "${var.vpc_id}"

  # HTTP access from a specific CIDRS
  ingress {
    from_port = "${var.elb_listener_lb_port}"
    to_port = "${var.elb_listener_lb_port}"
    protocol = "tcp"
    cidr_blocks = [ "${split(",", data.aws_ssm_parameter.in_access_allowed_cidrs.value)}" ]
  }

  # ingress {
  #   from_port = "${var.tsa_port}"
  #   to_port = "${var.tsa_port}"
  #   protocol = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "concourse_db" {
  name_prefix = "${var.prefix}-concourse-db"
  vpc_id = "${var.vpc_id}"

  # outbound internet access
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "allow_db_access_from_atc" {
  type = "ingress"
  from_port = 5432
  to_port = 5432
  protocol = "tcp"

  security_group_id = "${aws_security_group.concourse_db.id}"
  source_security_group_id = "${aws_security_group.atc.id}"
}

resource "aws_db_instance" "concourse" {
  depends_on = ["aws_security_group.concourse_db"]
  identifier = "concourse-master"
  allocated_storage = "50"
  engine = "postgres"
  engine_version = "9.6.6"
  instance_class = "${var.db_instance_class}"
  storage_type = "gp2"
  name = "concourse"
  username = "${data.aws_ssm_parameter.db_username.value}"
  password = "${data.aws_ssm_parameter.db_password.value}"
  vpc_security_group_ids = ["${aws_security_group.concourse_db.id}"]
  db_subnet_group_name = "${aws_db_subnet_group.concourse.id}"
  storage_encrypted = true
  backup_retention_period = 3
  backup_window = "09:45-10:15"
  maintenance_window = "sun:04:30-sun:05:30"
  apply_immediately = true
  final_snapshot_identifier = "concourse"

  lifecycle {
    ignore_changes = ["password"]
  }
}

resource "aws_db_subnet_group" "concourse" {
  name = "${var.prefix}-concourse-db"
  subnet_ids = ["${split(",", var.db_subnet_ids)}"]
}
