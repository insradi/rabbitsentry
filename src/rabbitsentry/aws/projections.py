"""Deliberate field projections: never persist complete SDK responses."""


def pick(data, fields):
    return {key: data[key] for key in fields if key in data}


def nested(data, field, fields):
    return {field: [pick(item, fields) for item in data[field]]} if field in data else {}


def instance(data):
    result = pick(
        data,
        [
            "InstanceId",
            "InstanceType",
            "VpcId",
            "SubnetId",
            "PrivateIpAddress",
            "PublicIpAddress",
            "LaunchTime",
            "PlatformDetails",
        ],
    )
    if "State" in data:
        result["State"] = pick(data["State"], ["Name"])
    result.update(nested(data, "SecurityGroups", ["GroupId"]))
    return result


def volume(data):
    result = pick(
        data,
        ["VolumeId", "Size", "VolumeType", "State", "Encrypted", "AvailabilityZone", "CreateTime"],
    )
    result.update(nested(data, "Attachments", ["InstanceId", "State", "Device"]))
    return result


def security_group(data):
    result = pick(data, ["GroupId", "GroupName", "VpcId"])
    if "IpPermissions" in data:
        rules = []
        for rule in data["IpPermissions"]:
            item = pick(rule, ["IpProtocol", "FromPort", "ToPort"])
            item.update(nested(rule, "IpRanges", ["CidrIp"]))
            item.update(nested(rule, "Ipv6Ranges", ["CidrIpv6"]))
            item.update(nested(rule, "UserIdGroupPairs", ["GroupId"]))
            item.update(nested(rule, "PrefixListIds", ["PrefixListId"]))
            rules.append(item)
        result["IpPermissions"] = rules
    return result


DB_FIELDS = [
    "DBInstanceIdentifier",
    "DBInstanceArn",
    "DBInstanceClass",
    "DBInstanceStatus",
    "DBClusterIdentifier",
    "DBClusterArn",
    "Status",
    "Engine",
    "EngineVersion",
    "EngineMode",
    "PubliclyAccessible",
    "StorageEncrypted",
    "StorageEncryptionType",
    "BackupRetentionPeriod",
    "DeletionProtection",
    "MultiAZ",
    "AvailabilityZone",
    "GlobalClusterIdentifier",
    "ReadReplicaSourceDBInstanceIdentifier",
    "ReadReplicaSourceDBClusterIdentifier",
    "ClusterScalabilityType",
    "DBClusterInstanceClass",
    "ReplicationSourceIdentifier",
    "VPCNetworkingEnabled",
    "InternetAccessGatewayEnabled",
]


def database(data):
    result = pick(data, DB_FIELDS)
    result.update(nested(data, "DBClusterMembers", ["DBInstanceIdentifier", "IsClusterWriter"]))
    result.update(nested(data, "VpcSecurityGroups", ["VpcSecurityGroupId", "Status"]))
    if "LimitlessDatabase" in data:
        result["LimitlessDatabase"] = pick(data["LimitlessDatabase"], ["Status"])
    if "RdsCustomClusterConfiguration" in data:
        result["RdsCustomClusterConfiguration"] = True
    return result


def key(data):
    result = pick(data, ["Status", "CreateDate"])
    if "AccessKeyId" in data:
        result["KeySuffix"] = data["AccessKeyId"][-4:]
    return result
