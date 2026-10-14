# AWS Cloud-Based Honeypot-as-a-Service
A pre-configured, cloud-based honeypot system built to attract, log, and analyze malicious behavior using Cowrie and Amazon Web Services including EC2, S3, CloudWatch, DynamoDB, Lambda, VPC, and Bedrock.

## Setup - Requires [Docker](https://docs.docker.com/get-docker/).
This honeypot system comes pre-configured and runs locally, so no AWS account is needed.

```bash
git clone https://github.com/aimatmia/AWS-Honeypot.git
cd AWS-Honeypot
docker compose up --build
```
