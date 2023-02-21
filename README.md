# AWS Devops skillbuilder

Browse courses on https://explore.skillbuilder.aws/learn You can log in with AWS
Partner or AWS account.

Note that links on left menu contains signature so anyone with the link can
watch your videos and update your progress :)
Completed:

acloud.guru completed courses
* Introduction to AWS https://learn.acloud.guru/course/intro-to-aws
* TODO: Mastering the AWS Well-Architected Framework https://learn.acloud.guru/course/aws-well-architected-framework/dashboard
* TODO: AWS Certified SysOps Administrator - Associate https://learn.acloud.guru/course/aws-certified-sysops-admin-associate/dashboard

udemy.com courses
* Ultimate AWS Certified SysOps Administrator Associate 2022 https://www.udemy.com/course/ultimate-aws-certified-sysops-administrator-associate/
* Practice Exams: AWS Certified SysOps Administrator Associate https://www.udemy.com/course/practice-exams-aws-certified-sysops-administrator-associate/


To test on AWS you can create new Organization asd@email.com so the test does
not affect much (except billing:) your account. After you sign in as root
(username is asd@email.com), create IAM account alias trkasd so all IAM users
can log in on https://trkasd.signin.aws.amazon.com/console
You should enable MFA (you can do in emulator by installing Google Authenticator
and inserting security code)
create IAM user with AdministratorAccess and use that
IAM user for all following tasks (create other IAM users, instances...)

# Billing

Use consolidated billing for aws organizations to see combined usage, share
volume pricing discount, receive single bill for multiple accounts.
You should enabled Budget alerts on
https://us-east-1.console.aws.amazon.com/billing/home#/budgets/overview
so you receive email when forecasted cost is greater than for example $10.

# IAM Identity and access management

https://explore.skillbuilder.aws/learn/course/479/play/1367/aws-identity-and-access-management-architecture-and-terminology
https://explore.skillbuilder.aws/learn/course/internal/view/elearning/120/introduction-to-aws-identity-and-access-management-iam

AWS re:Invent 2016: Become an AWS IAM Policy Ninja in 60 Minutes or Less
(SAC303) https://www.youtube.com/watch?v=y7-fAT3z8Lo

```
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html
{
  "Version": "2012-10-17", # use 2012-10-17 version to use policy variables like ${Account}
  "Statement": [
    {
      "Effect": "Allow", # Allow or Deny
      "Action": [ # this could we "*" or array
        "iam: ChangePassword",
        "iam: GetUser"
      ]
      "Resource": "arn:aws:iam::123456789012:user/${aws:username}" # object that statement covers
      "Condition": {"IpAddress": {"aws:sourceIp":"192.0.2.0/24"}}
    }
  ]
}
```

Evaluation logic: assumes Deny, if there is explicit Deny than it stops, if
there is allow for that resource/action than it Allow, otherwise it Deny
(impliciy deny).

Two types of policy:
https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_access-management.html#intro-access-resource-based-policies
* Identity policy (policy attached to IAM identities: user, group, role) grant
  only the actions your identity uses. Does not have principal property (who can
  assume this role) since it is attached to identity. Defines what actions on
  what resource is allowed.
* Resource-based policy: permission policy attach to a resource, like S3 or IAM
  role trust policy. What action a specified principal can perform on that
  resource and under what conditions. You can enable cross account access by
  specifing entire account or iam entities in another account as principal.

Video on "Role-Based Access in AWS"
Role is assummed programmatically and credentials are temporary and
automatically rotated (they do not have username and passwords).
Only IAM Role can have two policies: resource policy and one for principal.
Role defines Trust policy (which Principal can assume the role)
```
{
  "action": ["sts:AssumeRole"],
  "Principal": {"Service": "ec2.amazonaws.com"},

  "Principal": {"AWS": "arn:aws:iam::123123123123:user/test"}, # assume user
  "Principal": {"AWS": "123123123123"}, # assume account

  "Principal": {"Federated": "arn:aws:iam::123123123123:sampl-provider/ADFS"},
}
```
and Permission policy (what permissions the role can perform).

Resource-based policy is used on S3 bucket, SNS topic, SQS queue, KMS key
```
{
  "Statement": [{
    "Principal": {"AWS":["arn:aws:iam:123123123123"root]},
    "Effect": "Allow",
    "Action":["s3":"PutObject"],
    "Resource":"arn:aws:S3:::exampleBucket/*"
  }
}
```
To allow access for all users under one account
```
     "Principal": {
        "AWS": "*"
      },
      "Condition": {
        "StringEquals": {
          "AWS:SourceOwner": "121153076256"
        },
        "DateGreaterThan": {
          "aws:CurrentTime": ["2020-11-11T00:00:00z","2022-11-12T00:00:00z"]
        }
```

Principal is entity (root user, IAM user, or role) actor, can perform action or
access resources.
Action is list of API actions. You can use wild cards `?` for single char, `*`
for multiple characters like `"Action": "iam:*AccessKey*"` for all
create/delete/list/update AccessKey apis.
`NotAction` is used for exclusion (it is not `Deny` since other part of policy
can allow it, very different from case when other part is explicitly `Deny`).
Conditions all must match `AND`, with some value from array `OR`.
Variables: `${aws:username}`.

To restrict access you can use:
* AWS Organizations service control policy SCPs guardrails restrict except for
  admins
* IAM permissions boundaries: developers can manage roles safely
* VPC endpoint policies
* Block public access BPA

ARN format: arn:partition:service:region:account-id:resourcetype/resource
* arn:aws:iam::123123123123:user/Bob

You can use Access Analyzer to make least privilege permissions. Access Analyzer
helps you identify the resources in your organization and accounts, such as
Amazon S3 buckets or IAM roles, shared with an external entity. This lets you
identify unintended access to your resources and data, which is a security risk.
https://aws.amazon.com/iam/features/analyze-access/

Instead of writting policy to each user, you can write policy for a group and
use policy variables in `Resource` or in string comparisons in `Condition`
element, for example access to their home folder under mybucket.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": ["s3:ListBucket"],
      "Effect": "Allow",
      "Resource": ["arn:aws:s3:::mybucket"],
      "Condition": {"StringLike": {"s3:prefix": ["${aws:username}/*"]}}
    },
    {
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": ["arn:aws:s3:::mybucket/${aws:username}/*"]
    }
  ]
}
```

You can use S3 Batch operations to add tags or copy
https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-iam-role-policies.html
After creating a role, you should start creating a batch job.
When you run a job, if there is `Not available` Total objects listed in
manifest, than you should check permissions.

AWS IAM is a service to securely manage access to aws account services and
resources. Amazon Cognito manages identity inside applications, federate sign-in
using OIDC or SAML, or social sign in like Facebook

AWS IAM Identity center (successor to aws single sign-on), workforce
authentication and authorization.

# VPC

Videos:
components of vpc https://youtu.be/LX5lHYGFcnA?t=2921
https://explore.skillbuilder.aws/learn/course/206/play/7823/subnets-gateways-and-route-tables-explained

To create VPC you need to decide: Region where it is provisioned, IP range
(CIDR Classless Inter Domain Routing) for example 10.10.0.0/16 ie 10.10.x.x ip
addressing.
* 10.10.0.0/24 is too small since only 256 ip addresses 10.10.0.x available
* 172.16.0.0/12: from 172.16.0.0 to 172.31.255.255, this was default before
* 172.31.0.0/16 is now a default VPC cidr created automatically when account is
  created (also the igw, route table with local route and route to igw, nacl).
  For its subnets default is /20 172.31.0.0/20 networks are 172.31.16.0/20
  172.31.32.0/20 172.31.48.0/20...
  20 * 1=11111111.11111111.1111xxxx so they increases by 10000b=16, 32, 48, 64, 80
VPC are limited to a region (eu-west-1) but stretch across all Availability
Zones AZs (eu-west-1a, eu-west-1b and eu-west-1c). In each AZ we define subnet.
Subnets can be Private or Public and are limited to a single AZ. Subnet is a
place where we deploy instances and databases.

To create a subnet, you need VPC, Availability zone AZ and IP range for subnet,
for example 10.10.1.0/24.
Usually you create two subnets (in two different AZ) second is 10.10.2.x
To add connection, you need to create Internet gatwway IGW and attach to VPC.
Internet gateway IGW is device in VPC. You need to create if not exists.

Route tables are defining how to route traffic in subnets.
Determination which subnet is private and which is public is inside route
table. For public we need to create new route table, add route with destination
`0.0.0.0/0` and target IGW, and associate with subnet.

5 IPs are un-usable reserved .0 (network) .1 (gateway) .2 (dns) .3 (future) .255
(broadcast) http://jodies.de/ipcalc?host=192.168.0.5&mask1=26&mask2=

You can see inside instance in 10.10.1.0/24 subnet that local IPs are not using
gateway (gateway 0.0.0.0 which means to connect directly) but other IPs like
8.8.8.8 are going to gateway on `.1` address.
```
# check routes on the server, flags Up, Gateway, Host
route -n
Destination      Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0          10.10.1.1       0.0.0.0         UG    0      0        0 eth0
10.10.0.2        10.10.1.1       255.255.255.255 UGH   100    0        0 eth0
10.10.1.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0
10.10.1.1        0.0.0.0         255.255.255.255 UH    100    0        0 eth0
```

This table is the same for private instances (you need to temporary assign
route table with IGW to run `sudo apt install net-tools`). As long as IGW route
is assigned you can ping external IPs  `ping 8.8.8.8`.
To ping local resources you need to add `All ICMP - IPv4` from `0.0.0.0` to
security group used for those instances.
Alternativelly, you can use nmap with `-Pn` (threat all as online) or `-sn` (ping
scan, note that it does not discover instances when used with `-`, only direct
ip) for example to find all:
```
nmap -sn 10.1.3.22
nmap -Pn 10.1.3.22
nmap -Pn 10.1.3.-
nmap -Pn 10.1.1-3.-
nmap -Pn 10.1.0.0/16
```

Subnets define sub-networks that must be ip range of VPC, for example if VPC
is 10.3.0.0/16 than subnets can be /17 .../24... for example 10.3.1.0/24
(10.5.0.0/24 is not part of the VPC network 10.3.0.0/16)

Subnet is associated with route table, so when EC2 instance inside it wants to
communicate to internet outband, route table should contain IGW along with
default local entry (private subnet are not associated to route table which has
entry with IGW).
0.0.0.0/0 means any IP address.
```
# route table for public subnet
10.10.0.0/16  Local
0.0.0.0/0    IGW (Internet Gateway)
```
Inter subnet communications is possible because we use routes from VPC.

EC2 instance can use Elastic IP (static public IP address) to be able to get
inbound internet connections. Elastic is assigned to Elastic Network Interface
ENI (ENI is attached to EC2 instance).
You can use public ip addresses (no need to be static) but check "Auto assign
public IP" before you start instance since later you can not change that (and
instance can not get new ip address).
Note that even instance contains Public Ip Address but resides in subnet which
is not associated with route table that goes to IGW, you can not connect to it
outsite, and when you connect using bastion, you do not have access to internet
from the instance.

By default, in (private) subnet, instance can not connect to internet.
AWS managed Network Address Transation gateway service (NAT-GW) enables EC2
instances in private subnet to connect to internet outband. So here is route
table for private subnet to point to NAT-GW which is in public subnet so it can
connect to internet through IGW. NAT-GW is a service (machine managed by aws)
and should be enabled in each availability zone. You are charged by the hour for
each NAT-GW (IGW is free).
NAT-GW allows only outband connections and replay to this connections, prevent
the internet from initiating a connection to instances in private subnet. Allows
updates. For IPv6 use Egress only internet gateway
```
# route table for private subnet
10.10.0.0/16  Local
0.0.0.0/0    NAT-GW
```

To access private instances you need to connect to public instance which acts as
Bastion and once user is in VPC it can connect to other private instances.

VPC Endpoints is used to connect to Amazon S3 using Amazon private networks (not
going to internet using IGW but using private network through VPCE).
VPC Interface Endpoints is creating elastic network interface (ENI with IP
address) so you can use them to connect to external services using your own vpc
private network.

Aws Privatelink is used for a private, encrypted channel of communication
between its on-premises data center and a VPC in the AWS Cloud


To secure access you can use Network Access controll Network ACL and security
groups.
Network ACL is stateless so you need to enable both inbound and outbound ports.
By default it is allowing in and out all ports, but you can for example allow
443 inbound and 1025-65535 outbound (since http responds to an ephemeral port).
Security group is required for each EC2 instance. They are considered to be
statefull resources, they will remember if connection is from outside and allow
outbound traffic for that connection. By default they block all inbound and
allow all outboud, so you need to add allow inbound rules.

Difference between Network ACL (NACLs nackles) and Security Groups
https://youtu.be/LX5lHYGFcnA?t=9070
Security groups are on instance level, define only Allow rules, statefull
(return traffic is automatically allowed), all rules decide, applies only if
someone is atttached to to instance
NACL operates on subnet level, both allow and deny rules, stateless: return
traffic must be explicitly allowed, rules in number order decide and if applied
than other rules are not considered, applies to all subnet instances: good as
backup layer of defence if someone forgot to use security group.

Virtual VPN-IPSec
https://youtu.be/LX5lHYGFcnA?t=9498
Using Virtual gateway VGW
Direct Connect DX
VPC can be peered with other VPC.

On new instances Enhanced Networking is automatically enabled
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
```
ethtool -i ens5
driver: ena
```

# EC2

Cheaper Low cost ec2 instances can be obtained by fleet of Spot instances
https://aws.amazon.com/ec2/spot/pricing/
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-best-practices.html
https://aws.amazon.com/ec2/spot/instance-advisor/

You can use for steady state workloads using ECS on EC2.
Fargate (serverless compute for containers) is better for short workloads, like
tests.

Placement groups: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html
* Cluster : great network 10GB but high risk since they are on same rack,
  my-high-performance-group
* Spread: distinct hardware so we can spread on multiple AZ. limit to 7
  instances per placement group. maximize high availability my-critical-group
* Partition: up to 7 partitions per AZ, up to 100 instances, if one partition
  goes done, other should be fine. Kafka, Cassandra, Hadoop my-distributed-group

You can enable Termination protection `DisableApiTermination true` (so you can
not terminate from console, API or CLI). But if you shutdown from instance `sudo
shutdown`, it can be terminated if Shutdown behavior ec2 option
`InstanceInitiatedShutdownBehavior` is set to `terminate`
Difference between Terminate and Stop is that Stop will not remove any EBS disk,
but Terminate will mostly remove EBS disks (you can set up this)
You can Hibernate so the RAM is preserved  (kept on the root EBS) so starting
from hibernate is much faster, you do not need to boot OS. Use case for EC2
hibernate is when you have long running processing (it saves the ram) or you
need to boot up quickly. This is supported on On-Demand, Reserved and Spot
instances, but max hibernation is 60 days.
Hibernation has to be enabled when instance is creating, `Advance details > Stop
-Hibernate behavior > Enable` you need to enable encryption for root EBS
volume.

There is a limit for number of instances in one region (`InstanceLimitExceeded`)
for example 5 vCPU on-demand or spot instances. You need to start instance in
another region (changing AZ does not help since the limit is for whole region).
Search for `vcpu` on
https://us-east-1.console.aws.amazon.com/ec2/v2/home?region=us-east-1#Limits:
click on `Calculate vCPU limit` or `Request for increase`.
If Amazon does not have sufficient capacity to run new on demand instance in
specific AZ then error `InsufficientInstanceCapacity` will be returned.

Beside ON-demand instances which are most common (pay per second), you can use:
* Spot instances: short workload, cheap, can lose anytime
* Reserved instances: 1 or 3 years for long workloads, savings plan. Standard
  RIs you can change the instance size (large, 2xlarge), but not the type. Use
  convertible reserved instance when you need to exchange to another equal or
  greater configuration: instance family: type and size (m4.xlarge), operating
  system and tenancy (default/dedicated)
* Dedicated Hosts: book entire physical server, controll instance placement,
  more controll on hardware than dedicated instances
* Dedicated Instances: no other customers will share your hadrware
* Capacity Reservations: reserve capacity in specific AZ

Instance types:
* burstable T2/T3 uses CPU credits, credit usage/credit balance
* To change instance type you need to stop the EBS backed instance (you lose
  public ip address, but keeps instance id).

You can not purchase CPU credits, but you can change instance type.

SSH to the instance using: SSH, EC2 instance connect or Systems manager Session
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AccessingInstances.html?icmpid=docs_ec2_console
SSH private key (pem file, .cer file) should have 400 permission, or
`unprotected private key file` error.
```
chmod 400 ~/config/keys/pems/2022trk.cer
```
`permission denied` error is shown when ssh username is not correct.
`connection timed out` when SG, NACL, route table is no configured correctly, or
public ip is missing.
SG security group should allow TCP 22 from your ip or all ips 0.0.0.0

For EC2 Instance Connect inside AWS Console, it will push one time ssh public
key valid for 60 seconds.
Instance Connect will not work if you allow SSH 22 only from specific ip
address which is not aws IP address.  Also, if your user does not have
permission to SendSSHPublicKey you need to enable it:
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-set-up.html#ec2-instance-connect-configure-IAM-role
```
# a.json
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "ec2-instance-connect:SendSSHPublicKey",
        "Resource": [
            "arn:aws:ec2:us-east-1:606470370249:instance/i-0b7175eed059b8f41"
        ],
        "Condition": {
            "StringEquals": {
                "ec2:osuser": "ec2-user"
            }
        }
      },
      {
        "Effect": "Allow",
        "Action": "ec2:DescribeInstances",
        "Resource": "*"
      }
    ]
}
```

```
aws iam create-policy --policy-name add-send-ssh-to-instance --policy-document file://a.json
# copy policy arn and attach to the user who wants to use EC2 Instance Connect
aws iam attach-user-policy --policy-arn arn:aws:iam::606470370249:policy/add-send-ssh-to-instance --user-name read-only
```

If instance does not have public ip address, you need to use:
* EC2 Instance Connect CLI (web version requires public ip address)
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html#ec2-instance-connect-connecting-ec2-cli
  ```
  pip3 install ec2instanceconnectcli
  mssh i-0fd1ea6073db429fe
  # this did not work for me... works if instance has a public ip
  ```
* use public bastion instance (called jump box) inside same VPC
* AWS Direct connect, VPC peering (transit gateway) or VPN connection
  site-to-site
* ec2 status check can not be disabled
* ec2 scheduler events (reboot, retirement) are managed by aws and you can not
  schedule events manually.

# Route 53

You can use ALIAS record for zone apex (you can not use CNAME records on apex).
For ALIAS records you can not set TTL (it is using TTL of the target, if it a
another record, or 60 seconds if it is other AWS service)
Inspect with dig
```
dig alias.mydom.com
# this returns two ip addresses of load balancer

dig cname.mydom.com
# this return CNAME load balancer and than two ip addresses
```

You can configure Health check to monitor IP address or domain name and path

# AWS Load balancer LB

Diffrent types:
* Application LB: http, https, websocket, routes based on request
* Network LB: high troughput for TCP, TLS and UDP traffic. NLB has less latency
  (100ms vs 400ms for ALB). It has one static IP per AZ and you can assign
  Elastic IP (ex: helpfull for whitelistening specific IP). Target group can be
  EC2 instances, IP address (must be private, can point to your datacenter on
  premises) and can be ALB (combination of NLB and ALB gives you fixed IP
  addresses and ability to route baased on path). Healyh check is TCP, HTTP and
  HTTPS protocol.
* Classic LB: legacy
* Gateway LB: for 3th party virtual appliances: firewalls, intrusion detection
  and preventions systems. Operates at layer 3 network layer (IP protocol). You
  need to update Route table to route to GLB, which will distribute traffic to
  your virtual appliances for a security check, and if traffic is good, it can
  return to GLB and to target application. Uses GENEVE protocol on 6081 port.

ALB Load balancer security group should enable http and https access from
0.0.0.0/0 and ec2 instances should allow http (no need for https) only from load
balancer security group (if you do not need direct access, for example use SSM
Session manager for accessing the shell). Use the name like
`myapp-lb-http-https-sg-also-used-to-accept-http-on-ec2-sg`

ALB Load balancing can be:
* to multiple http applications across machines (target groups) routing based on
  hostname/path?httpparams (ex: good for microservices `/user` -> target group
  for User app, `/search` -> target group for Search app, `/job` -> target group
  on premises)
* to multiple applications on the same machine (ex: containers) use a Port
  mapping feature to redirect to dynamic port in ECS
* it supports redirect http -> https, and custom response, for example `/error`
  path will response with status 404 and message "this is not found"

ALB has fixed hostname XXX.region.elb.amazonaws.com and passes client IP as a
headers: X-Forwared-For and X-Forwared-Port and X-Forwared-Proto

Default load balancing algorithm is round robin, which distrubutes each requests
in turn. Another is LOR least outstanding requests, next instance is the
instance with the lowest number of pending/unfinished requests. Can not be used
with "Slow start duration" ex 30 seconds newly created instances receives 1,
than 2, then 3 requests (not a bunch of them in first second) Slow start mode is
defined on Target Group.
For apps that store session info locally, you can enable Sticky Sessions so ALB
will send to the same target (it can generate inbalanced load). Application
based: Cookie name is AWSALBAPP (or custom cookie when target generate the
cookie `_myapp_session`). Duration based cookies AWSALB.
NLB uses a flow hash (hash of Protocol, Source IP, Destination IP, Source Port,
Destination Port, TCP sequence number) and if that does not change, it will
be routed to the same instance.

Cross-zone Load balancing is to distribute evenly across all instances in all AZ
(ex: 2 in us-east-1a and 8 in us-east-1-b, each instance get 10% of traffic). It
is enabled by default so user is not charged for inter AZ communication. For NBL
and GLB is not enabled by default so user is charged for inter AZ data.

Target group weighting is that you can controller distribution of the traffict
Blue/green deployment ex: create a new instances that will receive 10% of the
traffic.

SSL is Secure Sockets Layer, newer version is TLS Transport Layer Security are
issues by CA Certificate Authorities (Letsencrypt, GoDaddy...). ALB is SSL
termination, it uses ACM Aws Certificate Manager to manage certs.
HTTPS listeners can use default and multiple certs to support multiple domains.
Different domains supported by SNI Server Name Indication, ALB pick correct SSL
cert and route to target group for that domain.

Generate new cert in ACM is easy, you just need to click on email confirmation
link for your domain, or change dns settings for your domain. Cert is issued by
Common Name (CN) Amazon RSA 2048 M01, and valid for 13 months. You need to add
CNAME that points to ALB ex: mylb-1386560557.us-east-1.elb.amazonaws.com

Connection draining is Time to complete "in-flight requests" while the instance
is de-regestering or unhealthy. Default is 300 seconds (5min). You can set 30s
if you have ready-to-use AMI. During this cooldown deregistration period ASG
will not launch or terminate additional instances to allow for metrics to
stabilize.
Y/ou can use ASG Lifecycle Hooks to pause ec2 instance in the terminating state
for troubleshooting.

New requests are send to other healthy instances. All healthy statuses are:
* initial: registering the target
* healthy
* unhealthy
* unused: target is not registered
* draining: de-registering the target
* unavailable: health check disabled

TG health check: if Target group contains only unhealthy targets, ELB routes
requests across it's unhealthy targets since it assume that health check is
wrong. `HealthyThresholdCount` default 5 and `UnhealthyThresholdCount` default
2 is how many checks every `HealthCheckIntervalSeconds` consecutive (in a row)
is enough to consider target healthy or unhealthy.


Common errors
https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/ts-elb-error-message.html#ts-elb-errorcodes-http504

5xx are server side errors, 5 looks like S (server) for example:
* HTTP 500: Internal server error (on the ELB itself)
* HTTP 502: Bad gateway (target is unreachable, check security groups)
* HTTP 503: Service unavailable, solution: ensure you have instances in every AZ
  ELB is configured to respond in
* HTTP 504: Gateway timeout (check target is registered), solution: check if
  keep-alive timeout settings on your ec2 is greater than the idle timeout of
  load balancer
* HTTP 561: Unauthorized

4xx are client errors (from browser to load balancer).
* HTTP 400: Bad request (mailformed request)
* HTTP 401: Unauthorized
* HTTP 403: Forbidden
* HTTP 408: Request timeout (idle timeout period expired)
* HTTP 460: Client closed connection
* HTTP 463: X-Forwarded For header with >30 IP (similar to mailformed request)
* HTTP 464: Unsportotred protocol

ClodWatch metrics:
* BackendConnectionErrors
* HealthyHostCount UnHealthyHostCount
* HTTPCode_Backend_2xx successfully requests
* HTTPCode_Backend_3xx redirected errors
* HTTPCode_ELB_4xx client error codes
* HTTPCode_ELB_5xx server error codes generated by LB
* Latency
* RequestCount
* RequestCountPerTarget
* SurgeQueueLength: number of pending requests, routing to healthy instance (max
  is 1024)
* SpilloverCount: number of rejected requests because the surge queue is full,
  to prevent this error you can monitor for `SurgeQueueLength` and auto scale

You can trace single user in logs using custom header `X-Amzn-Trace-Id` and you
might use for X-Ray

## Auto scalling group

Auto scalling can be manual, dynamic (based on CloudWatch metrics and target
value) and predictive (forecast for recurring cyclic patterns)

When you create ASG you need to define Launch template LT first. LT can have
multiple versions (default is used). LT can create on-demand and spot instances.
LT supports placement groups capacity reservations, dedicated hosts and multiple
instance types. LT can use T2 unlimited burst feature.:

ASG Health check is using Health check grace period (default 300s 5min) so new
instance will not be registered untill 5 minutes is passed.

ASG can be: simple step scaling (when CW alarm is triggered, ex CPU > 70% than
add 1 unit), target tracking (it will automatically create two CW alarms for
scale in (AlarmLow, remove instances) and scale out (AlarmHigh, add instances),
(scale up means using bigger instances, vertical scalling), scheduled (on known
used pattern) and predictive scaling (forecast load based on history).

Good metrics to scale on:
* `CPUUtilization` average CPU utilization across your instances
* `RequestCountPerTarget` stable number of requests per instance
* `Average Network In/Out` for NLB
Here are some ASG level metrics (enable on Auto Scaling group metrics
collection on Monitoring tab):
* `GroupMinSize`, `GroupMaxSize`
* `GroupInServiceInstaces`, `GroupTitalInstances`

Some reasons when scaling fails: reached MaximumCapacity, some LT dependency was
deleted (security group, key pair). If ASG fails 24h it will be suspended
administration suspension.

AWS Auto Scaling Plans, similar to ASG, but as separate service.

## EC2 Image Builder

Automatically create new image (select base image, update and customize), run
tests on new ec2 instance running new image and distribute image to regions.

You need to create a `MyImageBuilderEC2Role` role with
`Ec2InstanceProfileForImageBuilder` and `AmazonSSMMAnagedInstanceCore` policies.
Make sure you Deregister AMI and delete Image Build Version, so you do not get
charged.

Note that AMI is region locked, you can not share the same AMI between regions.
AMI is used when you want to move EC2 to another AZ (but there is no reason for
that since AZ are randomly enumerated by AWS).

# EBS

https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html
Block storage (you can update part of if) is provided with Elastic Block Storage
EBS (only one instance attached, or multi attach feature) instances has to be in
same AZ. You can increase volume size till 16 TB or you can attach multiple EBS
to single EC2 instance. To use on multiple instances you should use Elastic File
System EFS.
EBS is used as a root boot device launched from AMI.
There are Provisioned SDD, General purpose SSD, and HDD volume type. You can
make a backup using snapshot (they are incremental, save only what is changed).
* Provisioned IOPS SSD  io1 is 50 IOPS per GB, up to 64.000
  (expensive but very low latency, good for large databases) io2 500 per GB and
  durability 99.999% instead of 99.9% (256.000 IOPS)
* General puprose provisioned ssd gp2 gp3 3 IOPS per GB, up to 16.000 iops, for
  smaller than 1TB, it can burst up to 3.000 IOPS (good for boot volumes, dev)
* troughput optimized HDD (not ssd) st1 (low cost, up to 250 MB/s per TB, good
  for big data, datawarehouse, log proccessing frequently accesses through
  intensive)
* cold HDD sc1 up to 80 MB/s per TB, good for a fewer scans per day


## AWS Databases

RDS multi AZ deployment will use single DNS and it will automatically failover.
Database Type 	Use Cases	AWS Service
Relational	Traditional applications, ERP, CRM, e-commerce	Amazon RDS, Amazon Aurora, Amazon Redshift (cloud data warehouse)
Key-value	High-traffic web apps, e-commerce systems, gaming applications	Amazon DynamoDB In-memory Caching, session management, gaming leaderboards, geospatial applications Amazon ElastiCache for Memcached, Amazon ElastiCache for Redis
Document Content management, catalogs, user profiles Amazon DocumentDB (with MongoDB compatibility)
Wide column High-scale industrial apps for equipment maintenance, fleet management, and route optimization Amazon Keyspaces (for Apache Cassandra)
Graph Fraud detection, social networking, recommendation engines Amazon Neptune
Time series IoT applications, DevOps, industrial telemetry Amazon Timestream
Ledger Systems of record, supply chain, registrations, banking transactions Amazon QLDB

# Amazon CloudWatch

CloudWatch is a service for monitoring metrics and logs.
Basic monitoring is collecting every 5 minutes, detailed monitoring is paid and
it collects every 1 min.
It includes: `CPUUtilization` (processing power), `NetworkIn`/`NetworkOut`,
DiskReadOps/DiskWriteOps, DiskReadBytes/DiskWriteBytes (only when disk is
attached, not for ebs), `CPUCreditUsage` 1 cpu running 100% for 1 minute.
Status check metrics:
 * instance status: your individual instance (`StatusCheckFailed_Instance`)
   incorrect networking or startup conf, exhausted memory, corrupted file
   system. You need to reboot with new conf.
 * system status: AWS system or hardware on which the instance runs
 (`StatusCheckFailed_System`, `StatusCheckFailed`) loss of network connectivity,
 system power, software or hardware issues on physical host. You can move to the
 new host (if you used EBS) or wait for AWS to fix the issue
For Load balancer you can use: RequestCount, HealthyHostCount,
UnHealthyHostCount, TargetResponseTime, HTTP status codes
https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-cloudwatch-metrics.html

You can push custom metrics, for example RAM or from application, every second
if you want.
You can use PutMetricData API to send data using cli `aws cloudwatch
put-metric-data ...` or an Unified Cloudwatch agent installed with AWS System
Manager Agent SSM agent).
Example for memory util https://dev.to/drewmullen/send-memory-utilization-metrics-to-cloudwatch-5g28

procstat Plugin for CWAgent can collect specific proccess CPU time, memory.
Prefix is procstat_cpu_time, procstat_cpu_usage.

You can also export data using GetMetricData API.

https://explore.skillbuilder.aws/learn/course/external/view/elearning/203/introduction-to-amazon-cloudwatch
You can create alarm from EC2 instance -> right click -> Manage cloudwatch alarm

Event bridge is serverless event bus used to build event driven apps.
You can receive webhook on API Gateway which uses lambda to put event on
EventBridge which is using another lambda to put message to CloudWatch logs
stream.
Amazon EventBridge Overview and Integration with SaaS Applications
https://explore.skillbuilder.aws/learn/course/119/play/457/amazon-eventbridge-overview-and-integration-with-saas-applications
Amazon EventBridge is similar to cloudwatch events (deprecated), but with more
features. You can schedule automated snapshot of ebs.

Amazon cloudwatch logs insight perform queries and to search and analyze logs
interactively.

Using a custom metrics, CloudWatch filter and CloudWatch alarm you can get
notification when it is triggered more than 5 times per minute.

CloudWatch Composite Alarm monitors states of other alarms.

CloudWatch ServiceLens integrate health info in one place. It integrates with
AWS X-Ray to pinpoint performance bottleneck. Also integrates with Synthetics.

CloudWatch Synthetics, to monitor API from outside-in using canaries: scripts
that run on a schedule, written in Node.js or Python. Canaries offer access to
headless Google Chrome via puppeteer or selenium webdriver.
https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_Create.html

The AWS Health Dashboard is the single place to learn about the availability and
operations of AWS services. It displays relevant and timely information to help
users manage events in progress, and provides proactive notifications to help
plan for scheduled activities

# AWS Systems Manager SSM

It is a free service.
https://explore.skillbuilder.aws/learn/course/456/play/1308/aws-systems-manager
Run command, state manager, inventory, patch manager, automation, explorer,
Parameter Store, session manager (ssh), OpsCenter
AWS Systems Manager gives you visibility and control of your infrastructure on
operational data from multiple AWS services and allows you to automate
operational tasks across your AWS resources.

To install SSM follow
https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-setting-up-ec2.html
and create SSMInstanceProfile (this name from docs so we will use it) with
AmazonSSMManagedInstanceCore policy.

When creating a EC2 instance you need to attach created ec2 instance profile
SSMInstanceProfile.
For existing ec2, you can also attach/replace IAM Role SSMInstanceProfile, and it will
be automatically recognized with the Session Manager.
You can activate hybrid intance with script.

It is usefull to remotelly run commands without need to open inbound ssh ports,
and you can controll which commands can be performed and it is auditable.
Free service.

Command for cpu stress is: 
```
sudo amazon-linux-extras install epel -y
sudo yum install stress -y
stress --cpu 1 --timeout 10m
```

You can see that it is working by clicking on "Public IPv4 address" or "Public
IPv4 DNS" and removing "s" from "https://".

To connect you can use
```
export PEM_FILE=~/config/keys/pems/2022.pem
export SERVER_IP=174.129.128.6
ssh -i $PEM_FILE ubuntu@$SERVER_IP
ssh -i $PEM_FILE ec2-user@$SERVER_IP

curl $SERVER_IP
```

## SSM Run command

Documents can be: Managed (predefined) or custom documents (can be versioned).
Command is set of actions, document, targets and run time paramaters. Use case:
* monitoring
* bootstrap scripts (user data)
```
#!/bin/bash
# use Amazon linux AMI
yum update -y
yum install httpd -y
echo "hello from $(hostname -f)" > /var/www/html/index.html
systemctl start httpd
# automatically start on reboot
systemctl enable httpd

# on Amazon linux ami you should use service instead systemctl
service httpd start

# look for log on
cat /var/log/cloud-init-output.log
# if you are using AWS::Cloudformation::Init than it goes to
cat /var/log/cfn-init.log
cat /var/log/cfn-init-cmd.log
```

## SSM Automation

It uses Automation Runbook (SSM Documents of type Automation).
Can be triggered manually, EventBridge, on a schedule, by AWS Config
Use case: Restart instance, create an AMI, EBS snapshot...

## SSM Session manager

Another way to connect is using AWS Systems manager > Fleet manager
https://us-east-1.console.aws.amazon.com/systems-manager/managed-instances?region=us-east-1
EC2 need to create a role with `AmazonSSMManagedInstanceCore` policy (deprecated
policy is AmazonEC2RoleforSSM). In tutorials it is called instance profile so
put a name for a role `SSMInstanceProfile` and attach role to existing or new
ec2. No need for ssh keys nor open ports, you can use web or aws cli just
download and install session manager plugin with `sudo
./sessionmanager-bundle/install -i /usr/local/sessionmanagerplugin -b
/usr/local/bin/session-manager-plugin `
https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html#install-plugin-macos
```
aws ec2 describe-instances --query "Reservations[].Instances[].InstanceId"
# get instance id "i-0f3dde08ce455a628"
aws ssm start-session --target "i-0f3dde08ce455a628"
```

CloudTrail can intercept StartSession events if you need for compliance.
You can also restict to specific tags for other users, for example use policy
that permits `sssm:StartSession` Action with Condition StringLike
`"ssm:resourceTag/Environment": ["Dev"]`
Session log data can be sent to s3 or CloudWatch logs.
Preferences are on this tab
https://us-east-1.console.aws.amazon.com/systems-manager/session-manager/preferences

## SSM parameter store

It is used for configurations.
It stores passwords in plain text, so for passwords usually we use Secrets
Manager and we can also access them through name
`/aws/reference/secretsmanager/secret_ID_in_Secrets_Manager`
We also have data like
`/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x84_64-gp2` public

It is free for max 10_000 parameters, and max 4KB size.
$0.05 for new advanced parameter per month (max 8KB, and max 100_000 total) and
can be attached with Parameter Policy like expiration: EventBridge will receive
notification 15 days before password expires

Name `/my-app/dev/my-db-url` with value `some url` and one encrypted
`/my-app/dev/redis-password` with value `encripted***` you can use cli to access
them (and decrypt if you have access to key store)
```
aws ssm get-parameters --names /my-app/dev/db-url /my-app/dev/redis-password --with-decryption

aws ssm get-parameters-by-path --path /my-app/ --recursive
```

## AWS Secrets Manager

It can rotate passwords, database credentials, api keys.
It can store binaries.

## SSM State manager

Automate the process of keeping instances in state that you define.
Use case: bootstrap instance with software, updates on a schedule.
State manager association: defines the state we want.

## SSM Patch manager

Automates the patching managed nodes with security updates, for OS and
application.
Patch manager use patch baseline id so you can use SSM Run command to patch
speficic path groups.

SSM Maintenance windows: defines a schedule, duration, set of registered
instances, set of registered tasks.

# AWS CLI

Install and enable completion
```

# .bash_profile should source .bashrc
echo complete -C '/usr/local/bin/aws_completer' aws > ~/.bashrc
```
You need keys to connect
```
aws configure
AWS Access Key ID [**************4P5Q]:
AWS Secret Access Key [****************TCzr]:
```
You can check which profile you are using
```
# show current profile settings
aws configure list
# list all profile names
aws configure list-profile
# find details in file
cat ~/.aws/credentials
cat ~/.aws/config
```
To add another profile
```
aws configure --profile duleorlovic
# this will add [profile duleorlovic] to ~/.aws/config
# and [duleorlovic] to ~/.aws/credentials
# you can use in terraform provider "aws" { profile = "duleorlovic" }
aws ec2 describe-vpcs --profile duleorlovic
```
To change profile in shell you can export
```
export AWS_PROFILE=2022trk
```
Another way to change profile is to use different credentials file
```
AWS_SHARED_CREDENTIALS_FILE=~/.aws/credentials_duleorlovic aws s3 ls s3://my-trk-bucket
```


You can extract data
```
# list all public instances, using * returns array of arrays
aws ec2 describe-instances --query "Reservations[*].Instances[*].PublicIpAddress" --output=text
# this returns inline results since it is single array
aws ec2 describe-instances --query "Reservations[].Instances[].PublicIpAddress" --output=text
```
You can combine columns, for example to show ARN
```
aws ec2 describe-instances --region us-east-1 | jq -r '.Reservations[] | .OwnerId as $OwnerId | ( .Instances[] | { "ARN": "arn:aws:ec2:\(.Placement.AvailabilityZone[:-1]):\($OwnerId):instance/\(.InstanceId)", "AvailabilityZone": "\(.Placement.AvailabilityZone)", InstanceId, PublicDnsName, PrivateDnsName, Tags} )' | jq -s .
[
  {
    "ARN": "arn:aws:ec2:us-east-1:606470370249:instance/i-0b7175eed059b8f41",
    "AvailabilityZone": "us-east-1a",
    "InstanceId": "i-0b7175eed059b8f41",
    "PublicDnsName": "ec2-34-230-46-141.compute-1.amazonaws.com",
    "PrivateDnsName": "ip-172-31-90-19.ec2.internal",
    "Tags": [
      {
        "Key": "Name",
        "Value": "test"
      }
    ]
  }
]
```

# Data lifecycle management

DLM is used to create and delete EBS snapshots.

EBS snapshots are incremental backups, so only the blocks that have changed are
saved.

# S3

Objects storage (flat storage and each object has uuid) Scallable Simple Object
Storage S3. Buckets reside in region, but the name should be uniq across all
buckets.

Usage case is for: backups (EBS snapshot), media hosting, static websites.
User can create up to 100 buckets (or 1000 by submitting a service limit
increase). Bucket name should be uniq across all accounts. When deleted the name
is available after 24 hours. Name is between 3-63 characters long
Consist only of lowercase letters, numbers, dots (.), and hyphens (-)
Start with a lowercase letter or number
Not begin with xn-- (beginning February 2020)
Not be formatted as an IP address. (i.e. 198.68.10.2)
Use a dot (.) in the name only if the bucket's intended purpose is to host an
Amazon S3 static website; otherwise do not use a dot (.) in the bucket name
since SSL wild card certificate will work for
https://my.bucket.s3.us-east-1.amazonaws.com/my-file.txt
Virtual hosted-style URL https://bucket-name.s3.Region.amazonaws.com/key-name
Path style URL https://s3.Region.amazonaws.com/bucket-name/key-name is
deprecated.
Object size max 5 TB (upload using console is 160GB). Number of objects is
unlimited.
For upload bigger than 100MB you should use multipart upload and
AbortIncompleteMultipartUpload lifecycle rule
https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html
Objects consits: key (uniq in bucket), version ID, value, access control info
and metadata (like key value pairs, for example content-type, can not be changed
once object is created).
You can use ap to 10 tags key value pairs to each object (128 unicode chars for
key, and 256 chars for value).
Delete key myfile will permanently remove the object if version is not enabled.
If version is enabled, then delete key myfile will add a mar

https://my-bucket-name.s3.amazonaws.com/some/key-for-file.jpg
htpps://my-bucket-name.s3-us-east-1.amazonaws.com/some/key-for-file.jpg
(deprecated http:s//s3-us-east-1.amazonaws.com/my-bucket-name/key-for-file.jpg)

S3 supports resource based access controll (using Access controll list ACL and
bucket policy) and user based access controll.

To enable static website hosting, you need to:
* enable static web hosting in bucket properties
* disable "Block public access" for the bucket (also on account level if needed)
* write bucket policy to grant public read access, update `Bucket-Name` with
  your bucket name
  ```
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::Bucket-Name/*"
            ]
        }
    ]
}
  ```
* if bucket contains objects that are not owned by byt the bucket owner, you
  need object ACL access controll list that grants everyone read access

You can track costs by using AWS generated tag for cost allocation. This tag
will appear in AWS Cost explorer, AWS Budgets (can send alarms for usage
limits), AWS Cost and usage report.

https://docs.aws.amazon.com/cli/latest/userguide/cli-services-s3-commands.html
```
# make bucket
aws s3 mb s3://mybucket
# copy local file upload
aws s3 cp local-file s3://mybucket
# list all buckets
aws s3 ls
# list all files from bucket
asw s3 ls s3://mybucket
```

To move data you should use Aws DataSync (migrating by syncing, not one step),
Transfer Family. For streaming use Amazon Kinesis Data Streams and Firehose. For
offline Snowcone, snowball and snowmobile (for exabytes). Most cost optimal is
to transfer on premises data to multiple Snowball edge storage optimized devices
and copy to Amazon S3 and create lifecycle policy to transition the data into
AWS Glacier Currently, there is no way of uploading objects directly to S3
Glacier using a Snowball Edge.
https://aws.amazon.com/blogs/storage/using-aws-snowball-to-migrate-data-to-amazon-s3-glacier-for-long-term-storage/
AWS SMS server migration service does not have relation to shownball edge
(distractor).

For hybrid service you can use Aws Direct Connect (dedicated network connection
to AWS from on premise center) or aws Storage gateway (used to migrate data, ie
store on premise-data in an existing amazon S3 bucket, ie mount as NTF to AWS).
Those can not extend the VPC network.

AWS Outposts is service that offers the same AWS infrastructure to any
datacenter, so you can extend your VPC into the on-premises data center, and you
can communicate with private ip addresses.

To avoid internet you can use VPC Endpoints.

Security mechanisms for bucket.
Newly created bucket can only be accessed by the user who created it or the
account owner. Other users can access using:
* AWS IAM: use IAM policy for your users accessing your S3 resources (does not
  have principal)
  ```
  {
  "Version": "2012-10-17",
  "Statement": [
  {
  "Sid": "VisualEditor0",
  "Effect": "Allow",
  "Action": "s3:ListBucket",
  "Resource": "arn:aws:s3:::my-trk-bucket"
  }
  ]
  }
  ```
* Access control list ACL on individual objects (deprecated)
* Pre-signed URL: grant for limited time, note that presignigning can be
  successfully but actuall access will not work if credentials used in presign
  proccess does not have permission to read the object. If you used Security
  Token Service, presigned URL will expire when token expires.
  ```
  # this is default signature version so no need to set, max 7 days
  # aws configure set default.s3.signature_version s3v4
  aws s3 presign s3://my-trk-bucket/README.md --expires 60
  curl "https://my-trk-bucket.s3.us-east-1.amazonaws.com/README.md?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARYNKJHQQAVHT4P5Q%2F20220706%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220706T064501Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=2ff3afb8b8e0dcc308aaca2e49c94db3c83feaa26675ec35f4d29a47e4e8d7ae"
  ```
* Bucket policy

Bucket policy grant access to another account, user, role or service, it
requires `Principal` property. You use Bucket policy when you do not have access
to another account IAM policies, or IAM policies reaches the size limit.
```
{
  "Id": "Policy1657042359891",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1657042353716",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::my-trk-bucket/*",
      "Principal": {
        "AWS": [
          "arn:aws:iam::121153076256:user/admin"
        ]
      }
    }
  ]
}
```

Default is S3 standard tier. There is S3 IA or one zone IA (infrequent access)
you are charged for 128KB for object smaller than 128KB, or for 30days if you
remove before 30days)

Use Intelligent-Tiering Archive configurations under Properties tab on bucket,
to minimize the cost: Archive Access tier (90days min, minutes to retrieve up to
5 hours) or Deep archive access tier (180 days min, up to 5 hours to retreive).
Object smaller than 128KB are always in frequent access tier.

Glacier Instant retrieval (access once a quarter), Glacier Flexible retrieval
(retrieval 1min to 12 hours), Glacier Deep Archive (access once or twice in
year, retrieval 12-48hours).

For data that is not often accessed but requires high availability choose Amazon
S3 standard IA.

Cost includes https://aws.amazon.com/s3/pricing/
* storage price: based on storage class, eventual monthly monitoring fee
* request and data retrieval: every api/sdk call
* data transfer: price for bandwith in and out of s3, except data transferred in
  from the internet (upload), data transferred out to EC2 in the same region as
  bucket, data transferred out to cloudfront
* management and replication: price for features like S3 inventory, analytics,
  object tagging

Enable bucket logs under Properties -> Server access logging, you can add
prefix. It will log all GET requests, API calls.
https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html
It is advisable to create lifecycle rule under Management, to clear old logs.
Use Athena to query logs
https://aws.amazon.com/premiumsupport/knowledge-center/analyze-logs-athena/

Object Lock using a write-once-read-many WORM model to prevent object from being
deleted or overwritten. It can be enabled only during bucket creation. It
enables versioning. You can configure Default retention mode so no users (or
governance users) can delete or overwrite during that period (for example 1year)

# AWS CloudTrail

Track all user activity across your AWS accounts, see actions that user, role or
service has taken.
Inspect logs with CloudWatch Logs or Athena
https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html
For example find who when how deleted a.csv
```
SELECT * FROM "s3_access_logs_db"."mybucket_logs" WHERE key = 'a.csv' AND operation LIKE '%DELETE%' limit 10;
```
Find sum uploaded files from IP 188.2.98.99 and last month
```
SELECT SUM(bytessent) as uploadTotal FROM s3_access_logs_db.mybucket_logs WHERE RemoteIP='188.2.98.99'
AND parse_datetime(RequestDateTime, 'dd/MMM/yyyy:HH:mm:ss Z') BETWEEN
parse_datetime('2022-06-06', 'yyyy-MM-dd') AND parse_datetime('2022-07-07', 'yyyy-MM-dd');
```

Difference between server logs and cloudtrail (service for tracking API usage)
https://docs.aws.amazon.com/AmazonS3/latest/userguide/logging-with-S3.html
* server access logs delivers within a few hours, cloudtrail in 5min for data
  and 15min for management events
* cloudtrail is guaranteed and can be enabled on account, bucket or object level
  and can deliver logs to multiple destinations, and does not log authentication
  failures (but AcceessDenied is logged), json format.

When using a tags, you can write access policy with condition key
"s3:ExistingObjectTag/<key>": "<value>"
```
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::photobucket/*",
      "Condition": {
        "StringEquals": {
          "s3:ExistingObjectTag/phototype": "finished"
        }
      }
    }
  ]
}
```
also you can use tags in lifecycle rules, or cloudwatch metrics or croudtrail
logs.

To list all files, you can use API, but that could be expensive if there are a
lot of object. Instead you can enable Management -> Inventory service which will
periodically create cvs file in another bucket that you can query using Amazon
S3 Select (only SELECT command on csv json files) Note it has to be in one line
```
SELECT * FROM s3object s WHERE s._ 1 = 'a' LIMIT 5
```
https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-glacier-select-sql-reference-select.html
or Athena.

S3 event notification can be used to call lambda, sns or sqs service when some
api call occurs.

Amazon Simple Queue Service (SQS) is a fully managed message queuing service
that enables you to decouple and scale microservices, distributed systems, and
serverless applications. SQS eliminates the complexity and overhead associated
with managing and operating message-oriented middleware and empowers developers
to focus on differentiating work.
Used for asynchronous integration between application components

Cloudtrail log file integrity validation can be used for audit.

# AWS Config

AWS config (service that track configurations of resources) can be used to make
a sns notification when for example bucket become public using a managed rule
*s3-bucket-public-read-prohibited* also used to enable security and regulatory
compliance.
It can also prevent users for using other (unapproved) AMIs.
https://aws.amazon.com/blogs/security/how-to-use-aws-config-to-monitor-for-and-respond-to-amazon-s3-buckets-allowing-public-access/
Similar tools that check public access is enabled are:
* Aws IAM Access Analyzer - check pubcket policy ACL and access point policy
* AWS Trusted Advisor - check S3 bucket permissions, other Trudsted avisor
  checks can include cost optimization, performance, security, fault tolerance.
  For example security group created by Directory Service should not have
  unrestricted access. Approaching limits.
  Access advisor identify unnecessary permissions that have been assigned to
  users

Use S3 Storage Lens to optimize cost.

# AWS Directory Service

Managed microsoft active directory

# ECS

ECS backplane is communicating with ECS agent for placement decision.
Cluster is a logical group of EC2 instances on which Task is run. Task could be
running on EC2 or Fargate. Task can contain one or more container (usually
second is only for logging), defined in Task Definition (blueprint): which
images url and configuration.
Service is for long running applications, is a group of Tasks.

Task definition
```
{
  "containerDefinitions": [
    {
      "name": "simple-app",
      "image": "httpd:2.4:,
      "cpu": 256,  # 1 virtual CPU is 1024 units. Also "0.25 vCpu"
      "memory": 300, " "512 MB, 1 GB"
      "portMappings": [
        {
          "hostPort": 80,
          "coitnanerPort": 80,
          "protocol": "tcp"
        }
      ],
      "essential": true
    },
    {
      "name": "busybox",
      "image": "busybox",

    }
  ]
}
```

```
aws ecs create-task
aws ecs create-service
aws ecs run-task  --launch-type=FARGATE
```
Task placement: satisfy CPU, memory and network... than other constraints and
strategies: Location AZ us-east-1d, which instance type t2.small,
Strategies: Binpack (minimize number of EC2 instances, choose instance with the
least amount of memory or CPU, and all other tasks will be deployed there)
Spread (evenly on all ec2).
Constraints: Affinity 

TODO: https://ecsworkshop.com/introduction/ecs_basics/task_definition/

# EKS

Control-plane nodes: controller manager, cloud controller, scheduler and API
server that exposes Kubernetes API
Etcd: key value store
Worker nodes: Pod (group of one or more containers) similar to Task in ECS,
created from PodSpec. Runtime (Docker or containerd), kube-proxy and kubelet

# AWS Elastic beanstalk

AWS Service catalog is to manage infrastructure as code (IaC) templates.
AWS Elastic beanstalk is for deploys web applications.
https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/ruby-rails-tutorial.html#ruby-rails-tutorial-launch
Each Beanstalk environment will generate: ec2, ALB, S3, ASG, CW alarm,
CloudFormation stack and domain name.

# AWS CloudFormation

Use it to deploy to multiple AWS Regions quickly, automatically, and reliably.
Use a template json file and create a stack.

Download templates
https://github.com/jsur/aws-cloudformation-udemy/tree/master/1-introduction

```
---
Resources:
  MyInstance:
    Type: AWS::EC2::Instance
    Properties:
      AvailabilityZone: us-east-1a
      ImageId: ami-a4c7edb2
      InstanceType: t2.micro
```
You can upload template using cli `aws cloudformation create-stack help`
for example
```
# create
aws --profile 2022trk cloudformation create-stack --stack-name myteststack --template-body file://terraform/ec2.cloudformation.yml --parameters ParameterKey=KeyName,ParameterValue=2022

# list only CREATE_COMPLETE
aws --profile 2022trk cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE

# describe to find output
export PEM_FILE=~/config/keys/pems/2022.pem
export SERVER_IP=$(aws --profile 2022trk cloudformation describe-stacks --stack-name myteststack --query 'Stacks[0].Outputs[?OutputKey==`ServerIP`].OutputValue' --output text)
ssh -i $PEM_FILE ec2-user@$SERVER_IP sudo cat /var/log/cloud-init-output.log

# update
aws --profile 2022trk cloudformation update-stack --stack-name myteststack --template-body file://terraform/ec2.cloudformation.yml --parameters ParameterKey=KeyName,ParameterValue=2022

# destroy
aws --profile 2022trk cloudformation delete-stack --stack-name myteststack
```

There are over 224 resource types, type identifiers is:
`service-provider::service-name::data-type-name` for example
`AWS::EC2::Instance`
https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

Parameters can be: String, Number, CommaDelimitedList, List<Type>, AWS Parameter
and it can contain Constraints, AllowedValues, AllowedPattern.
```
---
Parameters:
  SecurityGroupDescription:
    Type: String
    Description: Security Group Description
```
Use function `!Ref MyParameter` (or `Fn::Ref`). When we `!Ref` parameter then it
returns paratemer value, and when we `!Ref` some resource then it returns
physical ID of the underlying resource.
You can `FN::GetAtt` to get attributes of the resources using dot syntax
```
NewVolume:
  Properties:
    AvailabilityZone:
      !GetAtt EC2Instance.AvailabilityZone
```

You can create a string using join and delimiter
```
!Join [ ":", [ a, b, c ] ]
# => "a:b:c"
```
Substitute values
```
!Sub
  - String # which contains ${VariableName}
  - { VariableName: VariableValue }
```

Pseudo parameters:
- `AWS::AccountId` example value `123456789012`
- `AWS::NotificationARNs` `{arn:aws:sns:us-east-!:123456789012:MyTopic}`
- `AWS::Region` example `us-east-1`
- `AWS::StackId` and `AWS::StackName`

Mappings are fixed variables (region, az, ami, environment like dev/prod)
```
Mappings:
  RegionMap:
    us-east-1:
      "32": "ami-a4c7edb2"
      "64": "ami-a4c7edb2"
```
Syntax is `!FindInMap [ MapName, TopLevelKey, SecondLevelKey ]`
Example use `!FindInMap [RegionMap, !Ref "AWS::Region", 32]`

Outputs are used to link with other Stack (you can not delete a stack if its
outputs are being referenced by another stack).
You can find return values in docs https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#aws-properties-ec2-instance-return-values

```
Outputs:
  StackSSHSecurityGroup:
    Value: !Ref MyCompanySSHSecurityGroup
    Export:
      Name: SSHSecurityGroup
  ServerIP:
    Description: Server IP address
    Value: !GetAtt MyInstance.PublicIp
```
Example usage is `!ImportValue SSHSecurityGroup`

Conditions are used to create based on parameter value or mappings using logic
functions: `!And`, `!Equals`, `!If`, `!Not`, `!Or`
```
Conditions:
  CreateProdResources: !Equals [ !Ref EnvType, prod ]
```
Example usage is in the same level as `Type`
```
Resources:
  MountPoint:
    Type: "AWS::EC2::VolumeAttachment"
    Condition: CreateProdResources
```

Use StackSet to provision across multiple accounts and regions (for example
deploy IAM role in each account).

Use `resource import` to bring existing resource to CloudFormation.
Prevent updates to critical resources by using a Stack policy.

Change set ...


AWS LightSail Use pre-configured development stacks like LAMP, Nginx, MEAN, and
Node.js. to get online quickly and easily.

AWS Application Discovery Service is used to collect data about the
configuration, usage, and behavior of its on-premises data centers to assist in
planning a migration to AWS

# Amazon Codeguru

Only for Jvm java and python

# CDK

https://aws.amazon.com/cdk/
defining Kubernetes configuration in TypeScript, Python, and Java

# Practice

acloudgutu courses https://acloudguru.com/learning-paths/aws-devops
twich https://aws.amazon.com/training/twitch/
TODO:   https://www.twitch.tv/videos/1439636257

https://www.amazon.com/s?k=aws+sysops+administrator+associate&crid=EILDGRZS79N1&sprefix=aws+sysops+admin%2Caps%2C162&ref=nb_sb_ss_ts-doa-p_1_16
https://www.examtopics.com/exams/amazon/aws-devops-engineer-professional/

# AWS Certified SysOps Administrator Associate SOA-CO2 Exam guide

* monitoring, logging, remediation
* reliability and business continuity
* deployment, provisioning and automation
* security and compliance
* networking and content delivery
* cost and performance optimization

preparation with AWS Certified Solutions Architect Associate SAA-CO2

SNS can not monitor Cloudwatch

# The Well Architected Framework

Set of principles/pillars:

* Operational excellence: all operations are code, documentation is updated
  automatically, make smaller changes you can rollback, iterate and anticipage
  failure (server down)
* security: identities have the least privileges required, know who did what
  when (traceability), security is woven into the fabric of the system, automate
  security task, encrypt data in transit and at rest, prepare for the worst
* cost optimization: consumption based pricing, measuring efficiency constantly,
  let aws do the work whenever possible
* reliability: recover from issues automatically, scale horizontally first for
  resiliency, reduce idle resources, manage change through automation
* performance efficiency: let aws do the work whenever possible, reduce latency
  through regions and AWS egde, serverless
* sustainability: adopt new more efficient hardware and software offerings

Agility is all about speed (experiment quickly), and not about autoscale or
elimination of wasted capacity.

# Aurora

Unparalleled high performance and availability at global scale compatible with
MySQL and PostgeSQL.
When primary instance of Amazon Auror cluster is unavailable, aurora promotes an
existing replica in another AZ to a new primary instance automatically.

# Amazon detective

Intrusion detection using cloudtrail logs, vpc flow logs , amazon guardduty, eks
audit logs.
GuardDuty monitors workloads for malicious activity.
Amazon GuardDuty is a threat detection service that continuously monitors your
AWS accounts and workloads for malicious activity and delivers detailed security
findings for visibility and remediation.

VPC flow logs capture information about ip traffic to and from network
interfaces.

Macie is used to detect sensitive data in S3 bucket.

AWS Shield is managed DDos protection

AWS WAF prevent web application common web exploits, such as bot traffic, sql
injection, cross site scripting xss

Amazon Inspector is for automated vulnerability detection and identify
uninstended network access

# Amazon DynamoDB

NoSQL database with automatic backup and restore, SLA 99.999%, optimize costs
with automatic scales up and down.

# Amazon Cloudfront

Cloudfront is content delivery network CDN.

AWS Global Accelerator is a networking tool, so when network is congested, is
optimizes the path to application.

# Amazon QuickSight

Business intelligence BI dashboard

# AWS Glue

Discover prepare and move from one source for analytics or machine learning.

# Amazon EMR

Run apache spark, hive, presto, hadoop,

# AWS OpsWorks

Configuration management service to automate operations with chef and puppet.
View operational data from multiple AWS services through a unified user
interface and automate operational tasks
This is alternative to AWS SSM.

# AWS CloudSHM

AWS CloudHSM helps you meet corporate, contractual, and regulatory compliance
requirements for data security.
It uses a highly secure hardware storage device to store encryption keys

User Control tower service to automate setup of multi account aws env, govern a

# Artifact

Compliance portfolio for Payment card industry PCI, Service Organization Control
SOC, NDA agreement, HIPPA, audit reports.

secure, compliant.

# Amazon OpenSearch service

Use elasticsearch and kabana to analize log, real-time application monitoring,
website search.

# AWS Step functions

Visual workflow service that helps developers use AWS services to build
distributed applications, automate processes, orchestrate microservices, and
create data and machine learning (ML) pipelines.

Amazon SageMaker Build, train, and deploy machine learning (ML) models for any
use case with fully managed infrastructure, tools, and workflows

Amazon simple workflow service swf, build apps that coordinate work across
distributed components

# Support plan

Business support plan includes 24/7 email,chat support
Enterprise support plan includes dedicated Technical Account Manager TAM, and
Concierge for account issue.
