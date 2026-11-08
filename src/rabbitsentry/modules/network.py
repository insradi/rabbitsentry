"""Security-group configuration checks; no reachability claims."""

from ipaddress import ip_network

from .base import Check, Evaluation, ModuleSpec, find

PORTS = {22, 3389, 1433, 3306, 5432, 6379, 9200, 11211, 27017}
CHECKS = {
    "NET001": Check(
        "Open administrative or database ports",
        "high",
        "Review each rule and restrict sources to the networks that need access. Confirm actual routes separately.",
        "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html",
    )
}


def collect(provider, region):
    return [provider.collect("ec2", "describe_security_groups", region)]


def inspect_rules(data):
    rules = data.get("IpPermissions")
    if not isinstance(rules, list):
        return [], True
    matches, unknown = [], False
    for rule in rules:
        protocol = str(rule.get("IpProtocol", "")).lower()
        if not protocol:
            unknown = True
            continue
        public = []
        for field, key in [("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")]:
            for source in rule.get(field, []):
                try:
                    network = ip_network(source[key], strict=False)
                    if network.prefixlen == 0:
                        public.append(str(network))
                except (KeyError, ValueError, TypeError):
                    unknown = True
        if not public:
            continue
        if protocol == "-1":
            matches.append({"protocol": "all", "sources": public, "ports": "all"})
        elif protocol in {"tcp", "6", "udp", "17"}:
            lower, upper = rule.get("FromPort"), rule.get("ToPort")
            if type(lower) is not int or type(upper) is not int or not 0 <= lower <= upper <= 65535:
                unknown = True
                continue
            ports = sorted(port for port in PORTS if lower <= port <= upper)
            if ports:
                matches.append({"protocol": protocol, "sources": public, "ports": ports})
    return matches, unknown


def evaluate(collections, account_id, region, policy, now):
    ctx = Evaluation("aws.network", CHECKS, account_id, region)
    groups = find(collections, "describe_security_groups")
    if ctx.empty(groups, CHECKS):
        return ctx.output
    for data in groups.items:
        if not data.get("GroupId"):
            ctx.emit(
                "NET001",
                ctx.scope,
                "unknown",
                "A group identifier is missing.",
                groups.evidence(data),
            )
            continue
        resource = ctx.subject("security_group", data["GroupId"])
        ctx.inventory(resource, groups, data)
        matches, unknown = inspect_rules(data)
        status = "fail" if matches else "unknown" if unknown else "pass"
        if unknown:
            ctx.gap(groups, "A group rule is missing required fields or has an invalid range.")
        reason = (
            "Rules permit unrestricted sources to listed ports or all protocols. This does not prove internet reachability."
            if matches
            else "Rule data is incomplete."
            if unknown
            else "No unrestricted administrative/database rule was found in this group's rules."
        )
        ctx.emit(
            "NET001", resource, status, reason, groups.evidence({**data, "matching_rules": matches})
        )
    return ctx.output


SPEC = ModuleSpec(
    "aws.network", "region", (("ec2", "describe_security_groups"),), CHECKS, collect, evaluate
)
