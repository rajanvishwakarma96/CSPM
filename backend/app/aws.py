import boto3

def assume_role(role_arn, external_id, region):
    sts=boto3.client("sts",region_name=region)
    p={"RoleArn":role_arn,"RoleSessionName":"cloud-autopilot-v2"}
    if external_id: p["ExternalId"]=external_id
    c=sts.assume_role(**p)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],region_name=region)

def caller_account(session):
    return session.client("sts").get_caller_identity()["Account"]

def discover(a):
    out=[]
    for region in a["regions"]:
        s=assume_role(a["role_arn"],a.get("external_id"),region)
        ec2=s.client("ec2",region_name=region)
        for rr in ec2.describe_instances()["Reservations"]:
            for x in rr["Instances"]:
                tags={t["Key"]:t["Value"] for t in x.get("Tags",[])}
                out.append({"resource_type":"EC2","resource_id":x["InstanceId"],
                    "region":region,"name":tags.get("Name",x["InstanceId"]),
                    "data":{"instance_type":x.get("InstanceType"),
                            "state":x.get("State",{}).get("Name")}})
        for x in ec2.describe_volumes()["Volumes"]:
            out.append({"resource_type":"EBS","resource_id":x["VolumeId"],
                "region":region,"name":x["VolumeId"],
                "data":{"size_gb":x.get("Size"),"attached":bool(x.get("Attachments"))}})
        for x in ec2.describe_security_groups()["SecurityGroups"]:
            out.append({"resource_type":"SECURITY_GROUP","resource_id":x["GroupId"],
                "region":region,"name":x.get("GroupName",x["GroupId"]),
                "data":{"vpc_id":x.get("VpcId")}})
        rds=s.client("rds",region_name=region)
        for x in rds.describe_db_instances()["DBInstances"]:
            out.append({"resource_type":"RDS","resource_id":x["DBInstanceIdentifier"],
                "region":region,"name":x["DBInstanceIdentifier"],
                "data":{"engine":x.get("Engine"),"class":x.get("DBInstanceClass"),
                        "publicly_accessible":x.get("PubliclyAccessible")}})
        ecs=s.client("ecs",region_name=region)
        for arn in ecs.list_clusters()["clusterArns"]:
            out.append({"resource_type":"ECS_CLUSTER","resource_id":arn.split("/")[-1],
                "region":region,"name":arn.split("/")[-1],"data":{}})
        lam=s.client("lambda",region_name=region)
        for x in lam.list_functions()["Functions"]:
            out.append({"resource_type":"LAMBDA","resource_id":x["FunctionArn"],
                "region":region,"name":x["FunctionName"],
                "data":{"runtime":x.get("Runtime"),"memory":x.get("MemorySize")}})
    s=assume_role(a["role_arn"],a.get("external_id"),a["regions"][0])
    for x in s.client("s3").list_buckets()["Buckets"]:
        out.append({"resource_type":"S3","resource_id":x["Name"],"region":"global",
            "name":x["Name"],"data":{}})
    return out
