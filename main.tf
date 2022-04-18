terraform {
	
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~>4.10"
    }
  }	
  required_version = ">= 0.13"
	  
  backend "s3" {
    profile        = "Final-Demo"
    region         = "us-east-1"
    key            = "terraform.tfstate"
    bucket         = "final-demo-jctbucket-21"
    dynamodb_table = "finaldemo-dynamodb-lock"
  }
}

provider "aws" {
  region  = "us-east-1"
  access_key = "AKIAU4IYCRAHFOXIOZK4"
  secret_key = "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"
}

# VPC *********************************************************************************************
resource "aws_vpc" "my-vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags = {
    Name = "Demo VPC"
  }
}
# VPC *********************************************************************************************

# SUBNETS *****************************************************************************************
# Web Public Subnet us-east-1a --------------------------------------------------------------------
resource "aws_subnet" "web-subnet-1" {
  vpc_id                  = aws_vpc.my-vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public Subnet us-east-1a"
  }
}

# Web Public Subnet us-east-1b --------------------------------------------------------------------
resource "aws_subnet" "web-subnet-2" {
  vpc_id                  = aws_vpc.my-vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "Public Subnet us-east-1b"
  }
}

# Application Private Subnet us-east-1a -----------------------------------------------------------
resource "aws_subnet" "application-subnet-1" {
  vpc_id                  = aws_vpc.my-vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false

  tags = {
    Name = "Private Application us-east-1a"
  }
}

# Application Private Subnet us-east-1b -----------------------------------------------------------
resource "aws_subnet" "application-subnet-2" {
  vpc_id                  = aws_vpc.my-vpc.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false

  tags = {
    Name = "Private Application us-east-1b"
  }
}

# Database Private Subnet us-east-1a --------------------------------------------------------------
resource "aws_subnet" "database-subnet-1" {
  vpc_id            = aws_vpc.my-vpc.id
  cidr_block        = "10.0.5.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "Private Database us-east-1a"
  }
}

# Database Private Subnet us-east-1b --------------------------------------------------------------
resource "aws_subnet" "database-subnet-2" {
  vpc_id            = aws_vpc.my-vpc.id
  cidr_block        = "10.0.6.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "Private Database us-east-1b"
  }
}

# SUBNETS *****************************************************************************************


# INTERNET GATEWAY ********************************************************************************
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.my-vpc.id

  tags = {
    Name = "Demo Internet Gateway"
  }
}
# INTERNET GATEWAY ********************************************************************************


# ELASTIC IP **************************************************************************************
resource "aws_eip" "elasticIP" {
  vpc = true
  tags = {
    Name = "Elastic IP for Demo"
  }
}
# ELASTIC IP **************************************************************************************


# NAT *********************************************************************************************
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.elasticIP.id
  subnet_id     = aws_subnet.web-subnet-1.id
  #availability_zone = "us-east-1a"
  tags = {
    Name = "NAT Gateway for Demo"
  }
}
# NAT *********************************************************************************************


# ROUTE TABLES ************************************************************************************

# Route Table for Public Subnets ------------------------------------------------------------------
resource "aws_route_table" "web-rt" {
  vpc_id = aws_vpc.my-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "Public Subnets Route Table"
  }
}

# Public Subnets Association with Web Route Table ------------------------------------------------
resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.web-subnet-1.id
  route_table_id = aws_route_table.web-rt.id
}

resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.web-subnet-2.id
  route_table_id = aws_route_table.web-rt.id
}

# Route Table for Private Web Subnets -------------------------------------------------------------
resource "aws_route_table" "wordpress-web-rt" {
  vpc_id = aws_vpc.my-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = {
    Name = "Private Subnets Web Route Table"
  }
}

# Private Subnets Association with Web Route Table ------------------------------------------------
resource "aws_route_table_association" "c" {
  subnet_id      = aws_subnet.application-subnet-1.id
  route_table_id = aws_route_table.wordpress-web-rt.id
}

resource "aws_route_table_association" "d" {
  subnet_id      = aws_subnet.application-subnet-2.id
  route_table_id = aws_route_table.wordpress-web-rt.id
}

# Route Table for Private Database Subnets --------------------------------------------------------
resource "aws_route_table" "database-web-rt" {
  vpc_id = aws_vpc.my-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = {
    Name = "Private Subnets Database Route Table"
  }
}

# Private Subnets Association with Database Route Table -------------------------------------------
resource "aws_route_table_association" "e" {
  subnet_id      = aws_subnet.database-subnet-1.id
  route_table_id = aws_route_table.database-web-rt.id
}

resource "aws_route_table_association" "f" {
  subnet_id      = aws_subnet.database-subnet-2.id
  route_table_id = aws_route_table.database-web-rt.id
}

# ROUTE TABLES ************************************************************************************


# EC2 INSTANCES ***********************************************************************************

# jumpbox (bastion)-1a - EC2 Instance -------------------------------------------------------------
resource "aws_instance" "jumpbox1a" {
  ami                    = "ami-0d5eff06f840b45e9"
  instance_type          = "t2.micro"
  availability_zone      = "us-east-1a"
  vpc_security_group_ids = [aws_security_group.public-sg.id]
  subnet_id              = aws_subnet.web-subnet-1.id
  user_data              = file("install_jumpbox.sh")
  key_name				 = "TF_key"

  tags = {
    Name = "jumpbox - 1a"
  }
}

# jumpbox (bastion)-1b - EC2 Instance -------------------------------------------------------------
resource "aws_instance" "jumpbox1b" {
  ami                    = "ami-0d5eff06f840b45e9"
  instance_type          = "t2.micro"
  availability_zone      = "us-east-1b"
  vpc_security_group_ids = [aws_security_group.public-sg.id]
  subnet_id              = aws_subnet.web-subnet-2.id
  user_data              = file("install_jumpbox.sh")
  key_name				 = "TF_key"

  tags = {
    Name = "jumpbox - 1b"
  }
}

# EC2 INSTANCES ***********************************************************************************


# MOUNT EFS, INSTALL WORDPRESS, SETUP WORDPRESS ***************************************************
data "template_file" "client" {
  template = file("./user_data/run_on_client.sh")
}
data "template_cloudinit_config" "config" {
  gzip          	= false
  base64_encode 	= true
  
  #First part of local config file
  part {
    
	content_type 	= "text/x-shellscript"
    content      	= <<-EOF
    #!/bin/bash
	# Script starts
	sudo su
	yum update -y
	# Mount EFS to /var/www/html
	sudo yum install nfs-utils -y -q
	sudo mkdir -p /var/www/html
	sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${aws_efs_file_system.efs.dns_name}:/ /var/www/html
    sudo chmod go+rw /var/www/html
	# Install php, httpd and WordPress
	sudo amazon-linux-extras install -y php7.4
	sudo yum install -y httpd
	sudo systemctl start httpd
	sudo systemctl enable httpd
	wget https://wordpress.org/latest.tar.gz
	tar -xzvf latest.tar.gz
	sudo cp -avr wordpress/* /var/www/html/
	sudo mkdir /var/www/html/wp-content/uploads
	sudo chown -R apache:apache /var/www/html/
	sudo chmod -R 755 /var/www/html/
    # Saves the RDS Endpoint path in file
	echo "${aws_db_instance.default.endpoint}" > /var/www/html/rds_endpoint.txt
	# WordPress setup
	cd /var/www/html/
	sudo su
	sed "s/database_name_here/demodb/" wp-config-sample.php > wp-config.php
	sed -i "s/username_here/admindb/" wp-config.php
	sed -i "s/password_here/D14m4nt3/" wp-config.php
	sed -i "s/localhost/$(cat rds_endpoint.txt)/" wp-config.php
	sudo chown -R apache:apache /var/www/html/
	sudo chmod -R 755 /var/www/html/
	EOF
  }

  #Second part
  part {
    content_type 	= "text/x-shellscript"
    content      	= data.template_file.client.rendered
  }
}
# MOUNT EFS, INSTALL WORDPRESS, SETUP WORDPRESS ***************************************************


# SECURITY GROUPS *********************************************************************************

# Public Security Group ---------------------------------------------------------------------------
# Create Web Security Group
resource "aws_security_group" "public-sg" {
  name        = "Public-SG"
  description = "Allow SSH and HTTP inbound traffic"
  vpc_id      = aws_vpc.my-vpc.id

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SG - Public Network"
  }
}

# Web Security Group ------------------------------------------------------------------------------
# Create Web Security Group
resource "aws_security_group" "web-sg" {
  name        		= "Web-SG"
  description 		= "Allow SSH and HTTP inbound traffic"
  vpc_id      		= aws_vpc.my-vpc.id

  ingress {
    description 	= "HTTP from VPC"
    from_port   	= 80
    to_port     	= 80
    protocol    	= "tcp"
    cidr_blocks 	= ["0.0.0.0/0"]
  }

  ingress {
    description     = "Allow traffic from SSH"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
	cidr_blocks 	= ["0.0.0.0/0"]
#   cidr_blocks 	= ["10.0.1.0/24", "10.0.2.0/24"]
  }

  ingress {
    description     = "Allow traffic from MySQL"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    cidr_blocks 	= ["0.0.0.0/0"]
#   cidr_blocks 	= ["10.0.5.0/24", "10.0.6.0/24"]
  }

ingress {
    description     = "Allow traffic from EFS"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    cidr_blocks 	= ["0.0.0.0/0"]
#   cidr_blocks 	= ["10.0.5.0/24", "10.0.6.0/24"]
  }

  egress {
    from_port   	= 0
    to_port     	= 0
    protocol    	= "-1"
    cidr_blocks 	= ["0.0.0.0/0"]
  }
 
  tags = {
    Name = "Web-SG"
  }
}

## Web Server Security Group -----------------------------------------------------------------------
## Create Web Server Security Group
#resource "aws_security_group" "webserver-sg" {
#  name        = "Webserver-SG"
#  description = "Allow inbound traffic from ALB"
#  vpc_id      = aws_vpc.my-vpc.id

#  ingress {
#    description     = "Allow traffic from web layer"
#    from_port       = 80
#    to_port         = 80
#    protocol        = "tcp"
#    security_groups = [aws_security_group.web-sg.id]
#  }

#  ingress {
#    description     = "Allow traffic from SSH"
#    from_port       = 22
#    to_port         = 22
#    protocol        = "tcp"
#    security_groups = [aws_security_group.web-sg.id]
#  }

#  ingress {
#    description     = "Allow traffic from MySQL"
#    from_port       = 3306
#    to_port         = 3306
#    protocol        = "tcp"
#    security_groups = [aws_security_group.web-sg.id]
#  }

#  egress {
#    from_port   = 0
#    to_port     = 0
#    protocol    = "-1"
#    cidr_blocks = ["0.0.0.0/0"]
#  }

#  tags = {
#    Name = "SG - Web Servers Network"
#  }
#}

# Database Security Group -------------------------------------------------------------------------
# Create Database Security Group
resource "aws_security_group" "database-sg" {
  name        = "Database-SG"
  description = "Allow inbound traffic from application layer"
  vpc_id      = aws_vpc.my-vpc.id

  ingress {
    description     = "Allow traffic from application layer"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    cidr_blocks     = ["10.0.3.0/24", "10.0.4.0/24"]

  }

  egress {
    from_port   = 32768
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SG - Database Network"
  }
}

# ELB Security Group ------------------------------------------------------------------------------
# Creating Security Group for ELB
resource "aws_security_group" "demosg1" {
  name        = "Demo Security Group"
  description = "Demo Module"
  vpc_id      = "${aws_vpc.my-vpc.id}"
# Inbound Rules
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # HTTPS access from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # SSH access from anywhere
#  ingress {
#    from_port   = 22
#    to_port     = 22
#    protocol    = "tcp"
#    cidr_blocks = ["0.0.0.0/0"]
#  }
# Outbound Rules
  # Internet access to anywhere
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SECURITY GROUPS *********************************************************************************


# RDS *********************************************************************************************

resource "aws_db_instance" "default" {
  identifier			 = "wordpress-db"
  allocated_storage      = 10
  db_subnet_group_name   = aws_db_subnet_group.default.id
  engine                 = "mysql"
  engine_version         = "8.0.27"
  instance_class         = "db.t3.micro"
  multi_az               = false
  db_name                = "demodb"
  username               = "admindb"
  password               = "D14m4nt3"
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.database-sg.id]
}

resource "aws_db_subnet_group" "default" {
  name       = "main"
  subnet_ids = [aws_subnet.database-subnet-1.id, aws_subnet.database-subnet-2.id]
}

output "rds_endpoint" {
  value = "${aws_db_instance.default.endpoint}"
}

# RDS *********************************************************************************************


# EFS *********************************************************************************************
# Create EFS resource
resource "aws_efs_file_system" "efs" {
   creation_token = "my-efs"
   performance_mode = "generalPurpose"
   throughput_mode = "bursting"
   encrypted = "true"
 tags = {
     Name = "efs-wordpress"
   }
   	provisioner "local-exec" {
		command = "echo ${aws_efs_file_system.efs.dns_name} > efs-dns-name.txt"
	}
}

# EFS Backup --------------------------------------------------------------------------------------
resource "aws_efs_backup_policy" "policy" {
  file_system_id = aws_efs_file_system.efs.id
  backup_policy {
    status = "ENABLED"
  }
}

# Creating Mount target of EFS --------------------------------------------------------------------
resource "aws_efs_mount_target" "mount" {
	file_system_id      		= aws_efs_file_system.efs.id
    subnet_id           		= aws_instance.jumpbox1a.subnet_id
	security_groups     		= [aws_security_group.web-sg.id]    
}
# EFS ***************************************************************************************** End


# KEY PAIR ****************************************************************************************
# Generate new private key
resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Generate a key-pair with above key
resource "aws_key_pair" "TF_key" {
  key_name   = "TF_key"
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "local_file" "TF-key" {
    content  = tls_private_key.rsa.private_key_pem
    filename = "TF_key.pem"
}

# Saving Key Pair for ssh login for Client if needed
resource "null_resource" "save_key_pair"  {
    provisioner "local-exec" {
    command = "echo  ${tls_private_key.rsa.private_key_pem} > mykey.pem"
    }
}
# KEY PAIR ****************************************************************************************


# AUTOSCALING *************************************************************************************

# LAUNCH TEMPLATE ---------------------------------------------------------------------------------
resource "aws_launch_template" "demo-lt" {
  name 						= "FinalDemo-LaunchTemplate"
  image_id 					= "ami-0d5eff06f840b45e9"
  instance_type 			= "t2.micro"
  key_name 					= "TF_key"
  vpc_security_group_ids 	= [aws_security_group.web-sg.id]
  user_data              	= data.template_cloudinit_config.config.rendered
}


# AUTO SCALING GROUP ------------------------------------------------------------------------------
resource "aws_autoscaling_group" "demo-asg" {
#  availability_zones 			= ["us-east-1a","us-east-1b"]
  desired_capacity   			= 2
  max_size           			= 6
  min_size           			= 2
  vpc_zone_identifier       	= [
								aws_subnet.application-subnet-1.id,
								aws_subnet.application-subnet-2.id
  ]								
  health_check_grace_period 	= 300
  health_check_type         	= "ELB"
  target_group_arns				= ["${aws_lb_target_group.app-wordpress-lb.arn}"]

  launch_template {
	id      					= aws_launch_template.demo-lt.id
    version 					= "$Latest"
  }
      
  enabled_metrics 				= [
								"GroupDesiredCapacity",
								"GroupInServiceInstances",
								"GroupMaxSize",
								"GroupMinSize",
								"GroupPendingInstances",
								"GroupStandbyInstances",
								"GroupTerminatingInstances",
								"GroupTotalInstances",
  ]

  metrics_granularity 			= "1Minute"

# Required to redeploy without an outage.
  lifecycle {
    create_before_destroy = true
  }

tag {
    key                 = "Name"
    value               = "WordPress ASG"
    propagate_at_launch = true
  }
}


# AUTO SCALING POLICY -----------------------------------------------------------------------------

resource "aws_autoscaling_policy" "web_policy_up" {
  name 						= "web_policy_up"
  scaling_adjustment 		= 1
  adjustment_type 			= "ChangeInCapacity"
  cooldown 					= 300
  autoscaling_group_name 	= "${aws_autoscaling_group.demo-asg.name}"
}

resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_up" {
  alarm_name 				= "web_cpu_alarm_up"
  comparison_operator 		= "GreaterThanOrEqualToThreshold"
  evaluation_periods 		= "2"
  metric_name				= "CPUUtilization"
  namespace 				= "AWS/EC2"
  period 					= "120"
  statistic 				= "Average"
  threshold 				= "70"

	dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.demo-asg.name}"
	}
    
  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = [ "${aws_autoscaling_policy.web_policy_up.arn}" ]
  
}

resource "aws_autoscaling_policy" "web_policy_down" {
  name 						= "web_policy_down"
  scaling_adjustment 		= -1
  adjustment_type			= "ChangeInCapacity"
  cooldown 					= 300
  autoscaling_group_name 	= "${aws_autoscaling_group.demo-asg.name}"
}

resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_down" {
  alarm_name 				= "web_cpu_alarm_down"
  comparison_operator		= "LessThanOrEqualToThreshold"
  evaluation_periods		= "2"
  metric_name 				= "CPUUtilization"
  namespace 				= "AWS/EC2"
  period 					= "120"
  statistic 				= "Average"
  threshold 				= "30"

	dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.demo-asg.name}"
	}
	
  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = [ "${aws_autoscaling_policy.web_policy_down.arn}" ]
}

# AUTO SCALING POLICY -----------------------------------------------------------------------------


# APPLICATION LOAD BALANCER ***********************************************************************

resource "aws_lb" "app-wordpress-lb" {
  name               			= "Demo-WordPress-LoadBalancer"
  internal           			= false
  load_balancer_type 			= "application"
  security_groups    			= [aws_security_group.web-sg.id]
  subnets            			= [aws_subnet.web-subnet-1.id, aws_subnet.web-subnet-2.id]
}

resource "aws_lb_target_group" "app-wordpress-lb" {
  name     						= "WordPress-ALB-TargetGroup"
#  target_type					= "instance"
  port     						= 80
  protocol 						= "HTTP"
  deregistration_delay			= 60
  vpc_id   						= aws_vpc.my-vpc.id
      
  health_check {
    path                		= "/"
    port                		= 80
    protocol            		= "HTTP"
    healthy_threshold   		= 2
    unhealthy_threshold 		= 4
    matcher             		= "200,301"
  }
  
#  stickiness {
#	enabled  = true
#	type = "lb_cookie"
#  }
}
    
resource "aws_autoscaling_attachment" "alb_autoscale" {
  lb_target_group_arn   		= "${aws_lb_target_group.app-wordpress-lb.arn}"
# autoscaling_group_name 		= "${aws_autoscaling_group.demo-asg.id}"
  autoscaling_group_name 		= "${aws_autoscaling_group.demo-asg.name}"
}

resource "aws_lb_listener" "app-wordpress-lb" {
  load_balancer_arn = aws_lb.app-wordpress-lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app-wordpress-lb.arn
  }
}

# APPLICATION LOAD BALANCER ***********************************************************************
