#!/bin/bash

# Gain root access
sudo su

# Script Variables
BucketName="INSERT BUCKET NAME HERE"
LifeCycleHookName="INSERT LIFECYCLE-HOOK-NAME HERE"
AutoScalingGroupName="INSERT AUTOSCALING GROUP NAME HERE"
Region="INSERT REGION HERE"

# Dynamically get the Instance ID from the Instance
InstanceID=`curl http://169.254.169.254/latest/meta-data/instance-id`

# Get Updates
yum update -y

# Install the apache web server
yum install -y httpd

# Change directory to apache website directory
cd /var/www/html/

# AWS Cli - Copy the deployment package from S3 
aws s3 cp s3://$BucketName/latest/index.zip ./index.zip

# Unzip the code package to the current directory
unzip index.zip -d .

# Remove the zip file
rm -f index.zip

# Start the Web Server
service httpd start

# Trigger the Autoscaling hook to complete and release the instance into service
aws autoscaling complete-lifecycle-action --lifecycle-hook-name "$LifeCycleHookName" --auto-scaling-group-name "$AutoScalingGroupName" --lifecycle-action-result CONTINUE --instance-id "$InstanceID" --region "$Region"