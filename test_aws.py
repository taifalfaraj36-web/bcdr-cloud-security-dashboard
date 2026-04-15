import boto3

iam = boto3.client('iam', region_name='eu-west-1')

response = iam.list_users()

print("IAM connection successful")
print(response)
