#!/bin/bash
yum update -y
# Install the apache web server
yum install -y httpd
# Change directory to apache website directory
cd /var/www/html/
# AWS Cli - Copy the deployment package from S3 
sudo aws s3 cp s3://{INSERT-BUCKET-NAME-HERE}/latest/index.zip ./index.zip
# Unzip the code package to the current directory
sudo unzip index.zip -d .
# Remove the zip file
sudo rm -f index.zip
# Start the Web Server
service httpd start