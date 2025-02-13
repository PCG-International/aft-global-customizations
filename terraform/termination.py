import boto3
import logging

def disable_ec2_termination_protection(instance, logger):
    instance_id = instance.id
    region = instance.meta.client.meta.region_name
    
    try:
        # Check termination protection status for EC2 instance
        ec2_client = boto3.client('ec2', region_name=region)
        response = ec2_client.describe_instance_attribute(
            InstanceId=instance_id,
            Attribute='disableApiTermination'
        )
    
        response_stop = ec2_client.describe_instance_attribute(
        InstanceId=instance_id,
        Attribute='disableApiStop'
        )
        
        protection_status = response['DisableApiTermination']['Value']
        stop_status=response_stop['DisableApiStop']['Value']
        
        if  protection_status or stop_status:
            logger.info(f"Termination protection or stop protection was enabled for EC2 instance {instance_id} in region {region}")
            # Disable termination abd stop protection for EC2 instances
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                DisableApiStop={'Value': False}
            )
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                DisableApiTermination={'Value': False},
            )
            logger.info(f"Termination and stop protection disabled for EC2 instance {instance_id} in region {region}")
        else:
            logger.info(f"Termination and stop protection were already disabled for EC2 instance {instance_id} in region {region}")
            
    except Exception as e:
        logger.error(f"Failed to disable stop or termination protection for EC2 instance {instance_id} in region {region}: {str(e)}")


def disable_rds_termination_protection(db_instance, logger):
    db_instance_id = db_instance['DBInstanceIdentifier']
    region = db_instance['AvailabilityZone'][:-1]
    protection_status = db_instance['DeletionProtection']

    if protection_status:
        logger.info(f"Termination protection was enabled for RDS instance {db_instance_id} in region {region}")
        try:
            # Disable termination protection for RDS instances
            rds_client = boto3.client('rds', region_name=region)
            rds_client.modify_db_instance(
                DBInstanceIdentifier=db_instance_id,
                DeletionProtection=False
            )
            logger.info(f"Termination protection disabled for RDS instance {db_instance_id} in region {region}")
        except Exception as e:
            logger.error(f"Failed to disable termination protection for RDS instance {db_instance_id} in region {region}: {str(e)}")
    else:
        logger.info(f"Termination protection was already disabled for RDS instance {db_instance_id} in region {region}")


def disable_elb_termination_protection(load_balancer, logger):
    load_balancer_name = load_balancer['LoadBalancerName']
    elb_arn = load_balancer['LoadBalancerArn']
    region = elb_arn.split(':')[3]  # Extract region from the ARN

    try:
        # Disable termination protection for Elastic Load Balancers
        elb_client = boto3.client('elbv2', region_name=region)
        elb_client.modify_load_balancer_attributes(
            LoadBalancerArn=load_balancer['LoadBalancerArn'],
            Attributes=[
                {
                    'Key': 'deletion_protection.enabled',
                    'Value': 'false'
                }
            ]
        )
        logger.info(f"Termination protection disabled for Elastic Load Balancer {load_balancer_name} in region {region}")

    except Exception as e:
        logger.error(f"Failed to disable termination protection for Elastic Load Balancer {load_balancer_name} in region {region}: {str(e)}")


def disable_emr_termination_protection(cluster, logger,region):
    cluster_id = cluster['Id']

    try:
        # Retrieve termination protection status for EMR cluster
        emr_client = boto3.client('emr', region_name=region)
        response = emr_client.describe_cluster(ClusterId=cluster_id)
        protection_status = response['Cluster']['TerminationProtected']
        
        if protection_status:
            # Disable termination protection for EMR clusters
            emr_client.set_termination_protection(
                JobFlowIds=[cluster_id],
                TerminationProtected=False
            )
            logger.info(f"Termination protection disabled for EMR cluster {cluster_id} in region {region}")
        else:
            logger.info(f"Termination protection was already disabled for EMR cluster {cluster_id} in region {region}")

    except Exception as e:
        logger.error(f"Failed to disable termination protection for EMR cluster {cluster_id} in region {region}: {str(e)}")


def disable_cloudformation_termination_protection(stack_name, logger, region):
    
    try:
        # Disable termination protection for CloudFormation stack
        cloudformation_client = boto3.client('cloudformation',region_name=region)
        cloudformation_client.update_termination_protection(
            EnableTerminationProtection=False,
            StackName=stack_name
        )
        logger.info(f"Termination protection disabled for CloudFormation stack {stack_name}")
        
    except Exception as e:
        logger.error(f"Failed to disable termination protection for CloudFormation stack {stack_name}: {str(e)}")

def disable_dynamodb_deletion_protection(table, logger, region):

    try:
        # Disable deletion protection for DynamoDB table
        dynamodb_client = boto3.client('dynamodb', region_name=region)
        response = dynamodb_client.update_table(
            TableName=table,
            DeletionProtectionEnabled=False
        )
        logger.info(f"Deletion protection disabled for DynamoDB table {table} in region {region}")

    except Exception as e:
        logger.error(f"Failed to disable deletion protection for DynamoDB table {table} in region {region}: {str(e)}")


def lambda_handler(event, context):
    # Set up logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    boto3.set_stream_logger(name='botocore.credentials', level=logging.ERROR)

    # Retrieve all available regions
    ec2_resource = boto3.resource('ec2')
    regions = [region['RegionName'] for region in ec2_resource.meta.client.describe_regions()['Regions']]

    for region in regions:
        logger.info(region)

        rds = boto3.client('rds', region_name=region)
        elasticbeanstalk = boto3.client('elasticbeanstalk', region_name=region)
        elb = boto3.client('elbv2', region_name=region)
        efs = boto3.client('efs', region_name=region)
        ec2 = boto3.resource('ec2', region_name=region)
        emr = boto3.client('emr', region_name=region)
        cloudformation = boto3.client('cloudformation',region_name=region)
        dynamodb = boto3.client('dynamodb', region_name=region)


        # Disable termination protection for EC2 instances
        instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        for instance in instances:
            disable_ec2_termination_protection(instance, logger)

        # Disable termination protection for RDS instances
        db_instances = rds.describe_db_instances()['DBInstances']
        for db_instance in db_instances:
            disable_rds_termination_protection(db_instance, logger)

        # Disable termination protection for Elastic Load Balancers
        response = elb.describe_load_balancers()
        elbs = response['LoadBalancers']
        for load_balancer in elbs:
            disable_elb_termination_protection(load_balancer, logger)

        # Disable termination protection for EMR clusters
        clusters = emr.list_clusters()['Clusters']
        for cluster in clusters:
            disable_emr_termination_protection(cluster, logger, region)

        # Disable termination protection for CloudFormation stacks
        stacks = cloudformation.list_stacks(StackStatusFilter=[
            'CREATE_IN_PROGRESS', 'CREATE_FAILED', 'CREATE_COMPLETE',
            'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE',
            'DELETE_IN_PROGRESS', 'DELETE_FAILED', 'UPDATE_IN_PROGRESS',
            'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS', 'UPDATE_COMPLETE',
            'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_FAILED',
            'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
            'UPDATE_ROLLBACK_COMPLETE', 'REVIEW_IN_PROGRESS'])['StackSummaries']

        for stack in stacks:
            if stack['StackStatus'] != 'DELETE_COMPLETE':
                stack_name = stack['StackName']
                disable_cloudformation_termination_protection(stack_name, logger, region)

        # Disable deletion protection for DynamoDB tables
        response = dynamodb.list_tables()
        tables = response['TableNames']
        for table in tables:
            disable_dynamodb_deletion_protection(table, logger, region)