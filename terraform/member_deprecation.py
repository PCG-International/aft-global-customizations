import boto3
import os

def lambda_handler(event, context):
    # Create an STS client using the member account credentials
    sts_client = boto3.client('sts')
    orgs_client = boto3.client('organizations')
    aws_member_account_id = context.invoked_function_arn.split(":")[4]
    aws_organization_id = orgs_client.describe_organization()
    aws_management_account_id = aws_organization_id['Organization']['MasterAccountId']
    # Assume the IAM role in the management account
    role_arn = 'arn:aws:iam::{}:role/AssumedRoleMemberAccountLambda'.format(str(aws_management_account_id))
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AssumeRoleSession'
    )
    
    # Retrieve the temporary credentials
    credentials = assumed_role['Credentials']
    access_key = credentials['AccessKeyId']
    secret_key = credentials['SecretAccessKey']
    session_token = credentials['SessionToken']
    
    # Create a Lambda client using the temporary credentials
    lambda_client = boto3.client(
        'lambda',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    
    print(str(aws_member_account_id))
    print('{"AccountID": "%s"}'%(str(aws_member_account_id)))
    # Invoke the Lambda function in the management account
    function_name = 'deprecate-account'  # Replace with the actual function name
    response = lambda_client.invoke(
        FunctionName=function_name,
        Payload='{"AccountID": "%s"}'%(str(aws_member_account_id)),
        InvocationType='Event' 
    )