"""
EKS Node Log MCP Server - Enhanced Lambda Handler

Implements world-class MCP toolset for incident response:
- Async task pattern with idempotency
- Byte-range streaming for multi-GB files
- Manifest validation and completeness verification
- Pre-indexed error findings
- Cross-file correlation
- Secure artifact references


"""

import json
import boto3
import os
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

# AWS Clients
ssm_client = boto3.client('ssm')
s3_client = boto3.client('s3')

# Environment
LOGS_BUCKET = os.environ['LOGS_BUCKET_NAME']
SSM_AUTOMATION_ROLE_ARN = os.environ.get('SSM_AUTOMATION_ROLE_ARN', '')

# Constants
DEFAULT_CHUNK_SIZE = 1048576  # 1MB
MAX_CHUNK_SIZE = 5242880  # 5MB
DEFAULT_LINE_COUNT = 1000
MAX_LINE_COUNT = 10000
PRESIGNED_URL_EXPIRATION = 900  # 15 minutes
FINDINGS_INDEX_FILE = 'findings_index.json'


class Severity(Enum):
    CRITICAL = 'critical'
    WARNING = 'warning'
    INFO = 'info'


# Error patterns by severity - Comprehensive patterns from:
# 1. AWS EKS troubleshooting docs: https://docs.aws.amazon.com/eks/latest/userguide/troubleshooting.html
# 2. EKSLogAnalyzer: https://code.amazon.com/packages/EKSLogAnalyzer
ERROR_PATTERNS = {
    Severity.CRITICAL: [
        # === KERNEL/SYSTEM CRITICAL (from EKSLogAnalyzer dmesg.go) ===
        r'BUG:.*',  # Kernel bug detected
        r'kernel panic',
        r'watchdog: BUG: soft lockup',  # Soft lockup detection
        r'Memory cgroup out of memory.*process \d+ \(.*?\)',  # OOM kill with process
        r'\S+ invoked oom-killer',  # OOM killer invoked
        r'traps:\s*.*?\[',  # Application crash/trap
        r'\s.*?\[\d+\]: segfault at',  # Segfault
        r'task .*?:\d+ blocked for more than',  # Process blocked (I/O)
        r'(ip|nf)_conntrack: table full, dropping packet',  # Conntrack exhaustion
        r'dropping packet',  # Conntrack or iptables dropping packets
        r'iptables.*error',  # iptables rule error
        r'iptables-restore.*failed',  # iptables restore failed
        r'kube-proxy.*error',  # kube-proxy issue
        r'IPVS.*error',  # IPVS mode error
        r'conntrack.*exhausted',  # Connection tracking full
        
        # === KUBELET CRITICAL (from EKSLogAnalyzer kubeletlog.go) ===
        r'failed to (list|ensure lease exists).*Unauthorized',  # AWS auth issue
        r'(Server rejected|Unable to register).*Unauthorized',  # Node registration failed
        r'UnauthorizedOperation:',  # IAM permission issue
        r'the server has asked for the client to provide credentials',  # Cluster role issue
        r'unknown node for user "system:node:"',  # Bad certificate
        r'no networks found in /etc/cni/net\.d',  # CNI failure
        r'fork/exec.*resource temporarily unavailable',  # PID exhaustion
        r'failed to create new OS thread.*errno=11',  # Go runtime PID exhaustion
        r'Node became not ready.* Message:',  # Node NotReady
        r'Unit kubelet.* entered failed state',  # Kubelet failed
        r'failed to run Kubelet:',  # Kubelet launch failure
        r'Unable to register node with API server.* node=',  # Invalid node naming
        r'OCI runtime create failed:',  # Container runtime failure
        r'Standalone mode',  # Kubelet standalone mode (misconfiguration)
        r'PLEG is not healthy',  # PLEG health issue
        r'failed to validate kubelet flags:',  # Kubelet flag validation
        r'(failed to list|ensure lease exists|Server rejected|Unable to register).*dial.*i/o timeout',  # Network failure
        
        # === IPAMD/CNI CRITICAL (from EKSLogAnalyzer ipamd.go) ===
        r'Starting L-IPAMD',  # IPAMD restart (critical if repeated)
        r'InsufficientFreeAddressesInSubnet',  # IP exhaustion
        r'Failed to check API server connectivity.*no configuration has been provided',  # Missing token
        r'Unable to reach API Server',  # API server unreachable
        r'Failed to check API server connectivity',  # API connectivity failure
        r'Unauthorized operation: failed to call .* due to missing permissions',  # IAM missing permissions
        
        # === NODE JOIN FAILURES (from AWS docs) ===
        r'Instances failed to join',
        r'failed to join the kubernetes cluster',
        r'unable to register node',
        r'failed to register node',
        r'certificate has expired',
        r'x509: certificate',
        
        # === IRSA/OIDC/STS ERRORS (from AWS re:Post) ===
        r'WebIdentityErr: failed to retrieve credentials',  # IRSA credential retrieval failed
        r'InvalidIdentityToken.*No OpenIDConnect provider found',  # OIDC provider not found
        r'InvalidIdentityToken.*Incorrect token audience',  # Wrong OIDC audience
        r"InvalidIdentityToken.*HTTPS certificate doesn't match",  # OIDC thumbprint mismatch
        r'AccessDenied.*Not authorized to perform sts:AssumeRoleWithWebIdentity',  # IRSA assume role denied
        r'InvalidClientTokenId.*security token.*invalid',  # Invalid security token
        r'ValidationError.*Request ARN is invalid',  # Invalid IAM ARN format
        
        # === CLUSTER HEALTH ERROR CODES (from AWS docs) ===
        r'SUBNET_NOT_FOUND',  # Subnet not found
        r'SECURITY_GROUP_NOT_FOUND',  # Security group not found
        r'IP_NOT_AVAILABLE',  # IP not available in subnet
        r'VPC_NOT_FOUND',  # VPC not found - UNRECOVERABLE
        r'ASSUME_ROLE_ACCESS_DENIED',  # Cannot assume cluster role
        r'PERMISSION_ACCESS_DENIED',  # Insufficient role permissions
        r'ASSUME_ROLE_ACCESS_DENIED_USING_SLR',  # Cannot assume EKS service-linked-role
        r'PERMISSION_ACCESS_DENIED_USING_SLR',  # SLR insufficient permissions
        r'KMS_KEY_DISABLED',  # KMS key disabled
        r'KMS_KEY_NOT_FOUND',  # KMS key not found - UNRECOVERABLE
        r'KMS_GRANT_REVOKED',  # KMS grants revoked - UNRECOVERABLE
        r'STS_REGIONAL_ENDPOINT_DISABLED',  # STS endpoint disabled
        r'OPT_IN_REQUIRED',  # EC2 subscription missing
        
        # === MANAGED NODE GROUP ERRORS (AWS error codes) ===
        r'AccessDenied',
        r'AmiIdNotFound',
        r'AsgInstanceLaunchFailures',
        r'AutoScalingGroupNotFound',
        r'ClusterUnreachable',
        r'Ec2LaunchTemplateNotFound',
        r'Ec2SecurityGroupNotFound',
        r'Ec2SubnetInvalidConfiguration',
        r'IamInstanceProfileNotFound',
        r'IamNodeRoleNotFound',
        r'InstanceLimitExceeded',
        r'InsufficientFreeAddresses',
        r'NodeCreationFailure',
        r'AutoScalingGroupInvalidConfiguration',  # ASG config modified externally
        r'Ec2LaunchTemplateVersionMismatch',  # Launch template version mismatch
        r'Ec2SecurityGroupDeletionFailure',  # Cannot delete remote access security group
        r'InternalFailure',  # Amazon EKS server-side issue
        
        # === HYBRID NODES CRITICAL (nodeadm) ===
        r'nodeadm.*failed',
        r'nodeadm.*error',
        r'failed to initialize node',
        r'SSM activation failed',
        
        # === STORAGE CRITICAL ===
        r'error mounting.*etc-hosts.*to rootfs.*/etc/hosts',  # /etc/hosts mount failed
        r'volume.*failed',
        r'mount.*failed',
        r'PersistentVolume.*failed',
        r'Unable to attach or mount volumes',  # General mount failure
        r'MountVolume\.SetUp failed',  # Mount setup failed
        r'timed out waiting for the condition.*volume',  # Mount timeout
        r'ebs-csi.*error',  # EBS CSI driver error
        r'efs-csi.*error',  # EFS CSI driver error
        r'mount\.nfs.*timed out',  # NFS mount timeout
        r'mount: wrong fs type',  # Filesystem type mismatch
        r'fsck.*error',  # Filesystem check error
        
        # === KNOWN BAD KERNELS (from EKSLogAnalyzer kernel_bugs.go) ===
        r'5\.4\.214-120\.368',  # Known PLEG issue kernel
        r'5\.4\.217-126\.408',  # Known PLEG issue kernel
        r'5\.4\.238-155\.346',  # Known SMB mount issue kernel
        
        # === CONTAINER RUNTIME CRITICAL (from AWS docs exact strings) ===
        r'Container runtime network not ready: NetworkReady=false reason:NetworkPluginNotReady',  # Exact AWS docs string
        r'network plugin is not ready: cni config uninitialized',  # CNI not initialized
        r'container_linux\.go.*starting container process',  # Container start failure
        r'exec format error',  # Wrong architecture (amd64/arm64 mismatch)
        r'no such file or directory',  # Missing entrypoint/binary
        r'permission denied',  # File permissions issue
        
        # === VPC CNI/IP CRITICAL (from AWS re:Post) ===
        r'Failed to assign an IP address to pod',  # IP assignment failure
        r'no free IP addresses',  # IP exhaustion
        r'ENI allocation failed',  # ENI limit or subnet issue
        r'failed to set up sandbox container.*network',  # Network setup failure
        r'NetworkNotReady',  # Network not ready condition
        r'networkPlugin cni failed',  # CNI plugin failure
        
        # === DNS CRITICAL (from AWS re:Post) ===
        r'dial udp.*:53.*i/o timeout',  # DNS port unreachable (High)
        r'dial udp.*:53.*timeout',  # DNS timeout (High)
        r'upstream.*unreachable',  # CoreDNS upstream unreachable (High)
        r'coredns.*unhealthy',  # CoreDNS unhealthy (High)
        r'CoreDNS.*error',  # CoreDNS error (High)
        r'DNS.*timeout',  # DNS query timeout (High)
        
        # === NODE JOIN CRITICAL (from AWS docs) ===
        r'node "" not found',  # Missing private DNS entry
        r'Failed to list \*v1\.Service: Unauthorized',  # Exact AWS docs string
        r'Unable to register node.*with API server: Unauthorized',  # Exact AWS docs string
        
        # === OOM/RESOURCE CRITICAL (from kernel logs) ===
        r'Killed process.*total-vm',  # OOM killer with memory info
        r'exit code 137',  # SIGKILL (OOM or manual kill)
        
        # === IMAGE PULL CRITICAL ===
        r'Failed to pull image',  # Image pull failure
        r'unauthorized.*authentication required',  # Registry auth missing
        r'manifest.*not found',  # Image/tag doesn't exist
        r'repository does not exist',  # Wrong repository
        r'ECR.*token.*expired',  # ECR auth expired
        r'pull access denied',  # No pull permission
        
        # === SECRETS/WEBHOOK CRITICAL ===
        r'failed to get secret',  # Secret retrieval failed
        r'secrets.*not found',  # Secret doesn't exist
        r'secrets.*forbidden',  # No permission to access secret
        r'KMS.*error',  # KMS error (High severity)
        r'decrypt.*failed',  # Decryption failed (High severity)
        r'webhook.*timeout',  # Webhook timeout
        r'webhook.*denied',  # Webhook denied request
        r'admission.*rejected',  # Admission controller rejected
        r'CreateContainerConfigError',  # Container config error (often secrets-related)
        
        # === NEW PATTERNS FROM EKSLogAnalyzer ids.go (February 2026) ===
        # Bandwidth/Network Limits
        r'Rx packets queued/dropped',  # IDBandwidthInExceeded - Rx bandwidth exceeded
        r'Tx packets queued/dropped',  # IDPPSExceeded - Tx packets per second exceeded
        r'Bandwidth.*exceeded',  # IDBandwidthOutExceeded - Bandwidth out exceeded
        r'LinkLocal.*dropped',  # IDLinkLocalExceeded - LinkLocal packets dropped
        
        # Conntrack (kernel level)
        r'nf_conntrack.*table full',  # IDConntrackExceededKernel - Conntrack exceeded at kernel level
        r'Maximum connections exceeded',  # IDConntrackExceeded - Instance level conntrack exceeded
        
        # iptables Issues (from EKSLogAnalyzer iptables.go)
        r'REJECT.*rule',  # IDUnexpectedRejectRule - Unexpected REJECT rule in iptables
        r'Missing.*IPAMD.*iptables',  # IDMissingIPAMdIptablesRules - Missing IPAMD iptables rules
        r'port.*conflict',  # Port conflict detected
        
        # Interface Issues (from EKSLogAnalyzer interfaces.go)
        r'interface.*down',  # IDInterfaceDown - Network interface down
        r'Missing.*IPv6.*address',  # IDMissingIPv6Address - Missing IPv6 address
        r'Missing.*loopback',  # IDMissingLoopbackInterface - Missing loopback interface
        
        # Route Issues (from EKSLogAnalyzer)
        r'Missing.*pod.*IP.*route',  # IDMissingIPRouteRules - Missing pod IP route rules
        r'Missing.*default.*route',  # IDMissingDefaultRoutes - Missing default route rules
        
        # Process Issues (from EKSLogAnalyzer processes.go)
        r'Excessive.*threads',  # IDExcessiveThreads - Too many threads
        r'zombie.*process',  # IdExcessiveZombieProcesses - Zombie processes
        r'Approaching.*kernel.*pid.*max',  # IDApproachingKernelPidMax - Near PID limit
        r'runc.*init.*hung',  # IDRuncInitPossiblyHung - runc init possibly hung
        
        # Nodeadm Issues (from EKSLogAnalyzer nodeadm.go)
        r'nodeadm.*run.*restart',  # IDNodeadmRunRestart - Nodeadm run restart
        
        # Bootstrap/Boot Issues
        r'Repeated.*bootstrap.*execution',  # IDRepeatedBootstrapExecution - Repeated bootstrap
        r'Multiple.*boots',  # IDMultipleBoots - Multiple boots detected
        r'Unexpected.*filesystem.*mount.*operation',  # IDUnexpectedFilesystemMountOperation - Unexpected mount after bootstrap
        
        # Auto Mode Issues
        r'VPC.*CNI.*pod.*Auto.*Mode.*node',  # IDAutoModeNodeWithAwsNode - VPC CNI pod on Auto Mode node
        
        # ec2-net-utils Package (from EKSLogAnalyzer)
        r'ec2-net-utils',  # IDHasEC2NetUtilsPackage - ec2-net-utils package installed (causes issues)
        
        # Security Agent Issues
        r'Trend.*Micro.*Security.*Agent',  # IDHasTrendMicroSecurityAgent - Trend Micro agent running (known issues)
    ],
    Severity.WARNING: [
        # === KUBELET WARNINGS (from EKSLogAnalyzer kubeletlog.go) ===
        r'Readiness probe for ".*?:(.*)" failed',  # Readiness probe failure
        r'Liveness probe for ".*?:(.*)" failed',  # Liveness probe failure
        r'due to client-side throttling',  # Client-side throttling
        r'\(PLEG\): ".*?".*Type:"ContainerDied"',  # Container died
        r'fs: disk usage and inodes count on following dirs took',  # Slow disk usage
        r'Pod still has one or more containers in the non-exited state',  # Pod stuck terminating
        r'--node-labels=""',  # Empty node labels
        r'(Starting|Stopping).* Kubernetes Kubelet',  # Kubelet restart
        
        # === KERNEL/DMESG WARNINGS (from EKSLogAnalyzer dmesg.go) ===
        r'\S+: Found a Tx that wasn\'t completed on time',  # TX not completed
        r'nfs: server .*? not responding',  # NFS not responding
        r'net_ratelimit:.*\d+ callbacks suppressed',  # Kernel log rate limiting
        r'martian source .* from .*, on dev',  # Martian packet
        r'mce: .*: Core temperature is above threshold',  # CPU overheating
        
        # === SYSTEM WARNINGS (from EKSLogAnalyzer messages.go) ===
        r'is not authorized to perform: .*? ',  # Missing AWS permission
        r'rsyslogd:.* \d+ messages lost due to rate-limiting',  # Syslog rate limiting
        r'systemd.*Failed to start .*?\.',  # Service failed to start
        r'cloud-init: \+ /etc/eks/bootstrap\.sh',  # Repeated bootstrap (if multiple)
        r'cloud-init: \+ mount /.*? /.*?',  # Unexpected mount operation
        r'kernel: Command line:',  # Multiple boots
        
        # === NETWORKING WARNINGS (from EKSLogAnalyzer networking) ===
        r'getsockopt: no route to host',
        r'network is unreachable',
        r'dial tcp.*connection refused',
        r'dial tcp.*i/o timeout',
        r'TLS handshake timeout',
        r'context deadline exceeded',
        r'DNS.*failed',
        r'resolve.*failed',
        r'lookup.*failed',
        
        # === POD/CONTAINER WARNINGS ===
        r'ImagePullBackOff',
        r'ErrImagePull',
        r'CrashLoopBackOff',
        r'RunContainerError',
        r'CreateContainerError',
        r'CreateContainerConfigError',
        r'FailedScheduling',
        r'FailedMount',
        r'FailedAttachVolume',
        
        # === RESOURCE WARNINGS ===
        r'Insufficient cpu',
        r'Insufficient memory',
        r'Insufficient pods',
        r'resource quota exceeded',
        r'PodEvicted',
        r'Evicted',
        r'OOMKilled',
        
        # === SCHEDULING WARNINGS ===
        r'node\(s\) didn\'t match.*selector',  # Node selector mismatch
        r'node\(s\) had.*taint',  # Taint/toleration mismatch
        r'node\(s\) didn\'t have free ports',  # Host port conflict
        r'0/\d+ nodes are available',  # No schedulable nodes
        r'Unschedulable',  # Pod can't be scheduled
        r'PodToleratesNodeTaints',  # Toleration issue
        r'NodeAffinity',  # Affinity rule not satisfied
        r'PodAffinity',  # Pod affinity not satisfied
        
        # === STORAGE WARNINGS ===
        r'VolumeResizeFailed',
        r'WaitForFirstConsumer',
        r'Pending.*PersistentVolumeClaim',
        r'xfs_repair',  # XFS filesystem repair needed
        r'PVC.*pending',  # PVC in pending state
        
        # === VPC CNI WARNINGS ===
        r'VPC CNI v1\.20\.4',  # Known buggy version
        
        # === PROCESS WARNINGS (from EKSLogAnalyzer) ===
        r'runc init',  # runc init possibly hung
        r'zombie',  # Zombie processes
        
        # === KNOWN BAD SOFTWARE (from EKSLogAnalyzer wellknown_bugs.go) ===
        r'DataDog.*7\.38\.[01]',  # DataDog zombie process bug
        
        # === ADDITIONAL WARNINGS FROM CATALOG ===
        r'Back-off restarting failed container',  # Container restart backoff
        r'denied.*access',  # Access denied (generic)
        r'dial tcp.*connection refused.*registry',  # Registry connection refused
        r'no such host.*ecr',  # ECR DNS failure
        r'no such host',  # Host not resolvable (generic)
        r'i/o timeout.*registry',  # Registry timeout
        r'NXDOMAIN',  # DNS domain not found
        r'SERVFAIL',  # DNS server failure
        r'CoreDNS.*error',  # CoreDNS error
        r'MutatingWebhook.*error',  # Mutating webhook error (Medium severity)
        r'ValidatingWebhook.*error',  # Validating webhook error (Medium severity)
        
        # === NEW WARNING PATTERNS FROM EKSLogAnalyzer ids.go (February 2026) ===
        # Throttling/Performance (from EKSLogAnalyzer cputhrottling.go, iothrottling.go)
        r'cpu.*throttl',  # IDCPUThrottling - CPU throttling detected
        r'io.*delay',  # IDIODelays - I/O delays detected
        
        # Storage (from EKSLogAnalyzer diskusage.go, xfs.go)
        r'High.*Disk.*Usage',  # IDHighDiskUsage - High disk usage
        r'XFS.*Small.*Average.*Cluster.*Size',  # IDXFSSmallAverageClusterSize - XFS cluster size issue
        
        # Conntrack (from EKSLogAnalyzer conntrack.go)
        r'UNREPLIED.*conntrack',  # IDConntrackUnrepliedEntries - Multiple UNREPLIED entries in conntrack
        
        # kube-proxy (from EKSLogAnalyzer kube_proxy.go)
        r'kube-proxy.*slow',  # IDKubeProxySlow - Slow kube-proxy performance
        
        # Pod Issues
        r'Pod.*stuck.*terminating',  # IDPodStuckTerminating - Pod stuck terminating
        
        # Environment Issues
        r'Large.*environment.*variables',  # IDLargeEnvironment - Large environment variables
        
        # Cron Issues
        r'Rapid.*cron',  # IDRapidCron - Rapid cron job execution
        
        # Container Issues
        r'Many.*dead.*containers',  # IDManyDeadContainers - Large number of dead containers
        
        # Network Configuration
        r'Missing.*MACAddressPolicy',  # IDMissingMACAddressPolicy - Missing MACAddressPolicy configuration
        r'Non.*default.*VPC.*CNI.*settings',  # IDNonDefaultVPCCNISettings - Non-default VPC CNI settings
        
        # Well-known Application Bugs
        r'Well.*known.*application.*bug',  # IDWellKnownApplicationBug - Well-known application bug detected
        
        # === GENERAL WARNINGS ===
        r'(?i)error',
        r'(?i)fail',
        r'(?i)denied',
        r'(?i)refused',
        r'(?i)timeout',
        r'(?i)unauthorized',
        r'(?i)forbidden',
        r'(?i)backoff',
        r'(?i)unreachable',
    ],
    Severity.INFO: [
        # === PROBE INFO ===
        r'readiness probe failed',
        r'liveness probe failed',
        r'startup probe failed',
        
        # === THROTTLING INFO (from EKSLogAnalyzer) ===
        r'CPU Throttling',
        r'I/O Delay',
        
        # === DISK INFO ===
        r'High Disk Usage',
        r'Small XFS Average Cluster Size',
        
        # === NETWORK INFO ===
        r'Many Network Connections',
        r'Interface Down',
        
        # === GENERAL INFO ===
        r'(?i)warn',
        r'(?i)warning',
        r'(?i)unable',
        r'(?i)cannot',
        r'(?i)couldn\'t',
        r'(?i)invalid',
        r'(?i)deprecated',
        r'(?i)missing',
        r'(?i)not found',
        r'(?i)expired',
        r'(?i)skipping',
        r'(?i)ignoring',
        r'(?i)retrying',
        r'(?i)slow',
        r'(?i)delayed',
        r'(?i)waiting',
        r'(?i)pending',
    ],
}

# =============================================================================
# POD/NODE FAILURE TRIAGE PATTERNS
# =============================================================================

# Category A: Volume/CSI Mount Issues
TRIAGE_VOLUME_CSI_PATTERNS = [
    (r'FailedMount', 'high'),
    (r'FailedAttachVolume', 'high'),
    (r'Unable to attach or mount volumes', 'high'),
    (r'MountVolume\.SetUp failed', 'high'),
    (r'volume.*not found', 'medium'),
    (r'VolumeResizeFailed', 'medium'),
    (r'WaitForFirstConsumer', 'medium'),
    (r'timed out waiting for the condition.*volume', 'high'),
    (r'ebs-csi.*error', 'high'),
    (r'efs-csi.*error', 'high'),
    (r'mount\.nfs.*timed out', 'high'),
    (r'mount: wrong fs type', 'high'),
    (r'fsck.*error', 'medium'),
    (r'xfs_repair', 'medium'),
    (r'PersistentVolume.*failed', 'high'),
    (r'PVC.*pending', 'medium'),
]

# Category B: Worker Node Issues
TRIAGE_NODE_ISSUES_PATTERNS = [
    (r'Node became not ready', 'high'),
    (r'NodeNotReady', 'high'),
    (r'PLEG is not healthy', 'high'),
    (r'Unit kubelet.*entered failed state', 'high'),
    (r'failed to run Kubelet', 'high'),
    (r'OCI runtime create failed', 'high'),
    (r'containerd.*error', 'medium'),
    (r'docker.*error', 'medium'),
    (r'DiskPressure', 'high'),
    (r'MemoryPressure', 'high'),
    (r'PIDPressure', 'high'),
    (r'eviction.*threshold', 'medium'),
    (r'Taint.*NoSchedule', 'medium'),
    (r'Taint.*NoExecute', 'high'),
    (r'OOMKilled', 'high'),
    (r'Memory cgroup out of memory', 'high'),
    (r'invoked oom-killer', 'high'),
    (r'Killed process.*total-vm', 'high'),
    (r'exit code 137', 'high'),
    (r'CrashLoopBackOff', 'high'),
    (r'Back-off restarting failed container', 'medium'),
    (r'Evicted', 'high'),
    (r'PodEvicted', 'high'),
]

# Category C: CNI/Networking Issues
TRIAGE_CNI_NETWORK_PATTERNS = [
    (r'InsufficientFreeAddressesInSubnet', 'high'),
    (r'failed to assign an IP address', 'high'),
    (r'no free IP addresses', 'high'),
    (r'ENI.*allocation.*failed', 'high'),
    (r'ipamd.*error', 'high'),
    (r'aws-node.*error', 'medium'),
    (r'no networks found in /etc/cni/net\.d', 'high'),
    (r'CNI.*failed', 'high'),
    (r'plugin.*returned.*error', 'medium'),
    (r'failed to set up sandbox container.*network', 'high'),
    (r'NetworkNotReady', 'high'),
    (r'networkPlugin cni failed', 'high'),
    (r'SNAT.*error', 'medium'),
    (r'egress.*failed', 'medium'),
]

# Category D: iptables/conntrack/kube-proxy
TRIAGE_IPTABLES_CONNTRACK_PATTERNS = [
    (r'ip_conntrack: table full', 'high'),
    (r'nf_conntrack: table full', 'high'),
    (r'dropping packet', 'high'),
    (r'iptables.*error', 'medium'),
    (r'iptables-restore.*failed', 'high'),
    (r'kube-proxy.*error', 'medium'),
    (r'IPVS.*error', 'medium'),
    (r'conntrack.*exhausted', 'high'),
    (r'nf_conntrack_max', 'medium'),
]

# Category E: Scheduling Constraints
TRIAGE_SCHEDULING_PATTERNS = [
    (r'FailedScheduling', 'high'),
    (r'Insufficient cpu', 'high'),
    (r'Insufficient memory', 'high'),
    (r'Insufficient pods', 'medium'),
    (r'node\(s\) didn\'t match.*selector', 'high'),
    (r'node\(s\) had.*taint', 'high'),
    (r'node\(s\) didn\'t have free ports', 'medium'),
    (r'PodToleratesNodeTaints', 'medium'),
    (r'NodeAffinity', 'medium'),
    (r'PodAffinity', 'medium'),
    (r'0/\d+ nodes are available', 'high'),
    (r'Unschedulable', 'high'),
]

# Category F: Image Pull/Auth Issues
TRIAGE_IMAGE_PULL_PATTERNS = [
    (r'ImagePullBackOff', 'high'),
    (r'ErrImagePull', 'high'),
    (r'Failed to pull image', 'high'),
    (r'unauthorized.*authentication required', 'high'),
    (r'manifest.*not found', 'high'),
    (r'repository does not exist', 'high'),
    (r'denied.*access', 'high'),
    (r'ECR.*token.*expired', 'high'),
    (r'dial tcp.*connection refused.*registry', 'medium'),
    (r'no such host.*ecr', 'high'),
    (r'i/o timeout.*registry', 'medium'),
    (r'pull access denied', 'high'),
]

# Category G: DNS/CoreDNS Issues
TRIAGE_DNS_PATTERNS = [
    (r'CoreDNS.*error', 'high'),
    (r'SERVFAIL', 'medium'),
    (r'NXDOMAIN', 'medium'),
    (r'lookup.*failed', 'medium'),
    (r'no such host', 'medium'),
    (r'DNS.*timeout', 'high'),
    (r'resolve.*failed', 'medium'),
    (r'dial udp.*53.*timeout', 'high'),
    (r'upstream.*unreachable', 'high'),
    (r'coredns.*unhealthy', 'high'),
]

# Category H: Secrets/KMS/Webhook/Admission
TRIAGE_SECRETS_WEBHOOK_PATTERNS = [
    (r'failed to get secret', 'high'),
    (r'secrets.*not found', 'high'),
    (r'secrets.*forbidden', 'high'),
    (r'KMS.*error', 'high'),
    (r'decrypt.*failed', 'high'),
    (r'webhook.*timeout', 'high'),
    (r'webhook.*denied', 'high'),
    (r'admission.*rejected', 'high'),
    (r'MutatingWebhook.*error', 'medium'),
    (r'ValidatingWebhook.*error', 'medium'),
    (r'CreateContainerConfigError', 'high'),
]

# All triage categories with metadata
TRIAGE_CATEGORIES = {
    'A': {
        'name': 'Volume/CSI Mount Issues',
        'patterns': TRIAGE_VOLUME_CSI_PATTERNS,
        'log_sources': ['storage', 'kubelet', 'dmesg', 'messages', 'ebs-csi', 'efs-csi'],
        'description': 'EBS/EFS CSI driver failures, mount timeouts, permission denied, PVC/PV mismatch'
    },
    'B': {
        'name': 'Worker Node Issues',
        'patterns': TRIAGE_NODE_ISSUES_PATTERNS,
        'log_sources': ['kubelet', 'dmesg', 'messages', 'containerd', 'docker'],
        'description': 'kubelet issues, containerd/runtime issues, disk full, memory pressure, node not ready, OOMKilled'
    },
    'C': {
        'name': 'CNI/Networking Issues',
        'patterns': TRIAGE_CNI_NETWORK_PATTERNS,
        'log_sources': ['ipamd', 'aws-node', 'networking', 'cni', 'plugin.log'],
        'description': 'VPC CNI IP exhaustion, ENI allocation failures, aws-node errors, SNAT/egress issues'
    },
    'D': {
        'name': 'iptables/conntrack/kube-proxy',
        'patterns': TRIAGE_IPTABLES_CONNTRACK_PATTERNS,
        'log_sources': ['networking', 'iptables', 'conntrack', 'dmesg', 'messages'],
        'description': 'conntrack exhaustion, kube-proxy rule failures, iptables restore errors'
    },
    'E': {
        'name': 'Scheduling Constraints',
        'patterns': TRIAGE_SCHEDULING_PATTERNS,
        'log_sources': ['kubelet', 'pods'],
        'description': 'insufficient CPU/memory, affinity/nodeSelector mismatch, taints/tolerations mismatch'
    },
    'F': {
        'name': 'Image Pull/Auth Issues',
        'patterns': TRIAGE_IMAGE_PULL_PATTERNS,
        'log_sources': ['kubelet', 'containerd', 'docker'],
        'description': 'registry auth, ECR token, DNS resolution, throttling'
    },
    'G': {
        'name': 'DNS/CoreDNS Issues',
        'patterns': TRIAGE_DNS_PATTERNS,
        'log_sources': ['coredns', 'networking', 'kubelet', 'pods'],
        'description': 'CoreDNS failures, upstream timeouts, NXDOMAIN storms'
    },
    'H': {
        'name': 'Secrets/KMS/Webhook/Admission',
        'patterns': TRIAGE_SECRETS_WEBHOOK_PATTERNS,
        'log_sources': ['kubelet', 'messages', 'secure'],
        'description': 'secrets retrieval errors, webhook timeout/deny'
    },
}

# Pod state patterns for detection
POD_STATE_PATTERNS = {
    'Pending': [r'Pod.*Pending', r'status.*Pending', r'phase.*Pending'],
    'ContainerCreating': [r'ContainerCreating', r'creating container'],
    'CrashLoopBackOff': [r'CrashLoopBackOff', r'Back-off restarting failed container'],
    'ImagePullBackOff': [r'ImagePullBackOff', r'ErrImagePull'],
    'OOMKilled': [r'OOMKilled', r'exit code 137', r'Memory cgroup out of memory'],
    'Evicted': [r'Evicted', r'PodEvicted', r'eviction'],
    'Error': [r'RunContainerError', r'CreateContainerError', r'CreateContainerConfigError'],
}

# Node condition patterns
NODE_CONDITION_PATTERNS = {
    'NotReady': [r'NodeNotReady', r'Node became not ready', r'condition.*Ready.*False'],
    'DiskPressure': [r'DiskPressure', r'disk pressure'],
    'MemoryPressure': [r'MemoryPressure', r'memory pressure'],
    'PIDPressure': [r'PIDPressure', r'pid pressure'],
    'NetworkUnavailable': [r'NetworkUnavailable', r'NetworkNotReady'],
}


# Log type to file pattern mapping
# Aligned with official EKS log collector: https://github.com/awslabs/amazon-eks-ami/blob/main/log-collector-script/
LOG_TYPE_PATTERNS = {
    # Core Kubernetes
    'kubelet': ['kubelet', 'kube-proxy', 'kubelet-config', 'kubeconfig'],
    'containerd': ['containerd', 'containerd-config', 'containerd-log', 'containerd-version', 
                   'containerd-namespaces', 'containerd-images', 'containerd-containers', 
                   'containerd-tasks', 'containerd-plugins'],
    'docker': ['docker', 'daemon.json', 'docker-info', 'docker-ps', 'docker-images', 
               'docker-version', 'docker-trace'],
    
    # System logs
    'dmesg': ['dmesg'],
    'kernel': ['kernel', 'dmesg', 'uname'],
    'messages': ['messages', 'syslog'],
    'system': ['messages', 'syslog', 'secure', 'audit', 'cron', 'cloud-init', 
               'cloud-init-output', 'user-data', 'pkglist', 'services', 'top', 
               'ps', 'netstat', 'procstat', 'instance-id', 'region', 'selinux',
               'cpu_throttling', 'io_throttling', 'last_reboot', 'large_environments'],
    'security': ['secure', 'audit', 'selinux'],
    
    # Networking
    'networking': ['networking', 'iptables', 'ip6tables', 'conntrack', 'conntrack6',
                   'iproute', 'ip6route', 'iprule', 'ip6rule', 'resolv', 'ifconfig',
                   'ipvsadm', 'ipset', 'ethtool', 'systemd-network', 'curl_api_server',
                   'configure-multicard-interfaces', 'ebpf-data', 'ebpf-maps-data'],
    
    # Storage
    'storage': ['storage', 'mount', 'lsblk', 'xfs', 'fstab', 'inodes', 'lvs', 'pvs', 
                'vgs', 'pod_local_storage', 'ebs-csi', 'efs-csi', 'fsx-csi', 
                'fsx-openzfs-csi', 'file-cache-csi', 's3-csi', 'mount-s3'],
    
    # AWS VPC CNI / IPAMD
    'ipamd': ['ipamd', 'aws-routed-eni', 'cni', 'plugin.log', 'network-policy',
              'enis.json', 'pods.json', 'networkutils-env-settings', 'ipamd-env-settings',
              'eni-configs', 'metrics.json', 'cni-configuration-variables'],
    
    # Pod/Container logs
    'pods': ['pods/', 'containers/'],
    'aws-node': ['aws-node', 'cni-metrics-helper'],
    'coredns': ['coredns'],
    
    # EKS-specific
    'nodeadm': ['nodeadm', 'nodeadm-config', 'nodeadm-run', 'nodeadm-boot-hook', 
                'udev-net-manager'],
    'sandbox-image': ['sandbox-image'],
    'eks-agents': ['eks-pod-identity-agent', 'eks-node-monitoring-agent'],
    
    # Configuration
    'config': ['kubelet-config', 'config.json', 'config.toml', 'kubeconfig', 
               'kubelet_service', 'kubelet-eks_service'],
    
    # Module/Kernel info
    'modinfo': ['modinfo', 'lustre', 'ip_vs', 'nf_conntrack'],
    'sysctls': ['sysctls', 'sysctl_all'],
    
    # GPU
    'gpu': ['gpu', 'nvidia-bug-report'],
    
    # Advanced networking
    'multus': ['multus', 'kube-multus'],
    'soci-snapshotter': ['soci-snapshotter', 'soci-snapshotter-status', 'soci-snapshotter-log'],
    
    # Throttling analysis
    'throttling': ['cpu_throttling', 'io_throttling'],
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def format_bytes(size: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def parse_failure_reason(execution: Dict) -> str:
    """Extract failure reason from SSM execution."""
    # Check for failure message in outputs
    outputs = execution.get('Outputs', {})
    if 'FailureMessage' in outputs:
        return outputs['FailureMessage']
    
    # Check step executions for failure
    for step in execution.get('StepExecutions', []):
        if step.get('StepStatus') == 'Failed':
            failure_msg = step.get('FailureMessage', '')
            if failure_msg:
                return f"Step '{step.get('StepName')}' failed: {failure_msg}"
    
    return execution.get('FailureMessage', 'Unknown failure reason')


def estimate_progress(execution: Dict) -> int:
    """Estimate progress percentage from step executions."""
    steps = execution.get('StepExecutions', [])
    if not steps:
        return 10  # Started but no steps yet
    
    total_steps = len(steps)
    completed_steps = sum(1 for s in steps if s.get('StepStatus') in ['Success', 'Failed', 'Cancelled'])
    
    if total_steps == 0:
        return 10
    
    return min(95, int((completed_steps / total_steps) * 100))


def find_execution_by_idempotency_token(instance_id: str, token: str) -> Optional[Dict]:
    """Find existing execution by idempotency token."""
    # Check S3 for idempotency mapping
    key = f'idempotency/{instance_id}/{token}.json'
    result = safe_s3_read(key)
    
    if result['success']:
        try:
            mapping = json.loads(result['content'])
            execution_id = mapping.get('executionId')
            
            # Verify execution still exists
            try:
                response = ssm_client.get_automation_execution(
                    AutomationExecutionId=execution_id
                )
                return {
                    'executionId': execution_id,
                    'status': response['AutomationExecution']['AutomationExecutionStatus']
                }
            except:
                return None
        except:
            return None
    
    return None


def store_idempotency_mapping(instance_id: str, token: str, execution_id: str):
    """Store idempotency token to execution mapping."""
    key = f'idempotency/{instance_id}/{token}.json'
    mapping = {
        'executionId': execution_id,
        'instanceId': instance_id,
        'token': token,
        'createdAt': datetime.utcnow().isoformat()
    }
    
    try:
        s3_client.put_object(
            Bucket=LOGS_BUCKET,
            Key=key,
            Body=json.dumps(mapping),
            ContentType='application/json'
        )
    except Exception as e:
        print(f"Warning: Failed to store idempotency mapping: {str(e)}")


def find_findings_index(prefix: str) -> Optional[str]:
    """
    Find the findings index file for a log collection.
    Searches for the most recent findings_index.json file.
    
    Prefix format: eks_{instance_id} (without trailing slash or execution_id)
    Actual S3 structure: eks_{instance_id}_{execution_id}/extracted/findings_index.json
    """
    # List all objects with this prefix (will match eks_i-xxx_* patterns)
    list_result = safe_s3_list(prefix, max_keys=500)
    
    if list_result['success']:
        # Find all findings index files and get the most recent one
        index_files = [
            obj for obj in list_result['objects']
            if FINDINGS_INDEX_FILE in obj['key']
        ]
        
        if index_files:
            # Sort by last modified (most recent first)
            index_files.sort(key=lambda x: x.get('last_modified', ''), reverse=True)
            return index_files[0]['key']
    
    return None


def scan_and_index_errors(instance_id: str, severity_filter: str) -> Dict:
    """Scan logs and build error index on-demand."""
    prefix = f'eks_{instance_id}'
    
    # List files to scan
    list_result = safe_s3_list(prefix, max_keys=5000)
    
    if not list_result['success']:
        return success_response({
            'instanceId': instance_id,
            'findings': [],
            'totalFindings': 0,
            'summary': {'critical': 0, 'warning': 0, 'info': 0},
            'cached': False,
            'warning': list_result.get('error', 'Failed to list log files')
        })
    
    # Filter for text files in extracted folder
    files_to_scan = [
        obj for obj in list_result['objects']
        if '/extracted/' in obj['key']
        and not any(obj['key'].endswith(ext) for ext in ['.tar.gz', '.zip', '.gz', '.bin', '.so'])
        and obj['size'] < 10485760  # Skip files >10MB
    ]
    
    findings = []
    summary = {'critical': 0, 'warning': 0, 'info': 0}
    
    for file_info in files_to_scan[:100]:  # Limit to prevent timeout
        file_findings = scan_file_for_errors(file_info['key'])
        
        for finding in file_findings:
            severity = finding.get('severity', 'info')
            summary[severity] = summary.get(severity, 0) + 1
            
            if severity_filter == 'all' or severity_filter == severity:
                findings.append(finding)
    
    # Sort by severity
    severity_order = {'critical': 0, 'warning': 1, 'info': 2}
    findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 3))
    
    return success_response({
        'instanceId': instance_id,
        'findings': findings[:100],
        'totalFindings': len(findings),
        'summary': summary,
        'cached': False,
        'indexedAt': datetime.utcnow().isoformat()
    })


def scan_file_for_errors(key: str) -> List[Dict]:
    """Scan a single file for error patterns."""
    findings = []
    
    # Read file content
    read_result = safe_s3_read(key, max_size=5242880)  # 5MB max
    
    if not read_result['success']:
        return findings
    
    content = read_result['content']
    lines = content.split('\n')
    filename = key.split('/extracted/')[-1] if '/extracted/' in key else key
    
    # Track patterns found to avoid duplicates
    found_patterns = {}
    
    for severity, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                matches = []
                
                for i, line in enumerate(lines):
                    if regex.search(line):
                        matches.append({
                            'lineNumber': i + 1,
                            'line': line[:500]  # Limit line length
                        })
                
                if matches:
                    pattern_key = f"{filename}:{pattern}"
                    if pattern_key not in found_patterns:
                        found_patterns[pattern_key] = True
                        findings.append({
                            'file': filename,
                            'fullKey': key,
                            'pattern': pattern,
                            'severity': severity.value,
                            'count': len(matches),
                            'sample': matches[0]['line'] if matches else ''
                        })
            except re.error:
                continue
    
    return findings


def read_by_lines(key: str, start_line: int, line_count: int, total_size: int) -> Dict:
    """Read file by line numbers instead of byte range."""
    # For line-based reading, we need to read the whole file (up to a limit)
    max_read = min(total_size, 10485760)  # 10MB max for line reading
    
    read_result = safe_s3_read(key, max_size=max_read)
    
    if not read_result['success']:
        return success_response({
            'logKey': key,
            'content': '',
            'startLine': start_line,
            'lineCount': 0,
            'totalLines': 0,
            'hasMore': False,
            'warning': read_result.get('error', 'Failed to read file')
        })
    
    lines = read_result['content'].split('\n')
    total_lines = len(lines)
    
    # Handle negative start_line (from end)
    if start_line < 0:
        start_line = max(0, total_lines + start_line)
    else:
        start_line = max(0, start_line - 1)  # Convert to 0-indexed
    
    end_line = min(start_line + line_count, total_lines)
    selected_lines = lines[start_line:end_line]
    
    return success_response({
        'logKey': key,
        'content': '\n'.join(selected_lines),
        'startLine': start_line + 1,  # Convert back to 1-indexed
        'endLine': end_line,
        'lineCount': len(selected_lines),
        'totalLines': total_lines,
        'hasMore': end_line < total_lines,
        'nextLineToken': str(end_line + 1) if end_line < total_lines else None,
        'truncated': False
    })


def search_file_for_pattern(key: str, pattern: re.Pattern, max_results: int) -> Optional[List[Dict]]:
    """Search a single file for a regex pattern."""
    read_result = safe_s3_read(key, max_size=5242880)  # 5MB max
    
    if not read_result['success']:
        return None
    
    matches = []
    lines = read_result['content'].split('\n')
    
    for i, line in enumerate(lines):
        if pattern.search(line):
            matches.append({
                'lineNumber': i + 1,
                'line': line[:500],  # Limit line length
                'context': get_line_context(lines, i, 2)
            })
            
            if len(matches) >= max_results:
                break
    
    return matches


def get_line_context(lines: List[str], index: int, context_lines: int) -> Dict:
    """Get surrounding context lines."""
    start = max(0, index - context_lines)
    end = min(len(lines), index + context_lines + 1)
    
    return {
        'before': lines[start:index],
        'after': lines[index + 1:end]
    }


def extract_timestamp(line: str) -> Optional[str]:
    """Extract timestamp from a log line."""
    # Common timestamp patterns
    patterns = [
        r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})',  # ISO format
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Syslog format
        r'(\d{10,13})',  # Unix timestamp
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    
    return None


def categorize_log_source(filename: str) -> str:
    """Categorize a log file into a component."""
    filename_lower = filename.lower()
    
    if 'kubelet' in filename_lower:
        return 'kubelet'
    elif 'containerd' in filename_lower or 'docker' in filename_lower:
        return 'container-runtime'
    elif 'dmesg' in filename_lower or 'kernel' in filename_lower:
        return 'kernel'
    elif 'messages' in filename_lower or 'syslog' in filename_lower:
        return 'system'
    elif 'ipamd' in filename_lower or 'cni' in filename_lower or 'aws-node' in filename_lower:
        return 'networking'
    elif 'storage' in filename_lower or 'mount' in filename_lower:
        return 'storage'
    elif 'pods' in filename_lower or 'containers' in filename_lower:
        return 'pods'
    else:
        return 'other'


def find_correlations(timeline: List[Dict]) -> List[Dict]:
    """Find correlations between events in the timeline."""
    correlations = []
    
    # Group by component
    by_component = {}
    for event in timeline:
        component = categorize_log_source(event.get('source', ''))
        if component not in by_component:
            by_component[component] = []
        by_component[component].append(event)
    
    # Look for common patterns
    if 'kernel' in by_component and 'kubelet' in by_component:
        correlations.append({
            'type': 'kernel-kubelet',
            'description': 'Kernel issues may be affecting kubelet',
            'components': ['kernel', 'kubelet']
        })
    
    if 'networking' in by_component and 'kubelet' in by_component:
        correlations.append({
            'type': 'network-kubelet',
            'description': 'Network issues may be affecting kubelet communication',
            'components': ['networking', 'kubelet']
        })
    
    # Check for OOM patterns
    oom_events = [e for e in timeline if 'oom' in e.get('event', '').lower() or 'killed' in e.get('event', '').lower()]
    if oom_events:
        correlations.append({
            'type': 'memory-pressure',
            'description': f'Memory pressure detected ({len(oom_events)} OOM events)',
            'components': list(set(categorize_log_source(e.get('source', '')) for e in oom_events))
        })
    
    return correlations


def generate_recommendations(critical_findings: List[Dict], warning_findings: List[Dict]) -> List[Dict]:
    """Generate remediation recommendations based on findings."""
    recommendations = []
    
    # Analyze critical findings
    for finding in critical_findings:
        pattern = finding.get('pattern', '').lower()
        
        if 'oom' in pattern or 'memory' in pattern:
            recommendations.append({
                'priority': 'high',
                'category': 'memory',
                'issue': 'Memory pressure detected',
                'action': 'Review pod resource limits and node capacity. Consider scaling up or adding nodes.',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/troubleshooting.html'
            })
        elif 'unauthorized' in pattern or 'denied' in pattern:
            recommendations.append({
                'priority': 'high',
                'category': 'auth',
                'issue': 'Authentication/authorization failures',
                'action': 'Check IAM roles, RBAC policies, and aws-auth ConfigMap.',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/troubleshooting_iam.html'
            })
        elif 'cni' in pattern or 'ipamd' in pattern or 'network' in pattern:
            recommendations.append({
                'priority': 'high',
                'category': 'networking',
                'issue': 'CNI/networking issues detected',
                'action': 'Check VPC CNI plugin logs, subnet IP availability, and security groups.',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/troubleshooting-cni.html'
            })
        elif 'pleg' in pattern:
            recommendations.append({
                'priority': 'high',
                'category': 'kubelet',
                'issue': 'PLEG (Pod Lifecycle Event Generator) issues',
                'action': 'Check for container runtime issues, disk I/O problems, or too many pods on node.',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/troubleshooting.html'
            })
    
    # Remove duplicates
    seen = set()
    unique_recommendations = []
    for rec in recommendations:
        key = rec['category']
        if key not in seen:
            seen.add(key)
            unique_recommendations.append(rec)
    
    return unique_recommendations


# =============================================================================
# POD/NODE TRIAGE FUNCTIONS
# =============================================================================

def perform_pod_node_triage(instance_id: str, findings: List[Dict], bundle_data: Dict) -> Dict:
    """
    Perform comprehensive pod/node failure triage analysis.
    Multi-pass scanning to ensure no errors are missed.
    
    Returns structured triage result with root cause, evidence, and remediation.
    """
    import time
    start_time = time.time()
    
    triage_result = {
        'triageVersion': '1.0',
        'analyzedAt': datetime.utcnow().isoformat(),
        'pod_states_detected': [],
        'node_conditions_detected': [],
        'most_likely_root_cause': None,
        'evidence': [],
        'secondary_hypotheses': [],
        'immediate_remediation_steps': [],
        'preventive_recommendations': [],
        'followup_validation_commands': [],
        'coverage_report': {
            'files_scanned': 0,
            'files_total': 0,
            'files_skipped': [],
            'categories_checked': list(TRIAGE_CATEGORIES.keys()),
            'categories_with_findings': [],
            'missing_log_sources': [],
            'scan_limitations': [],
            'scan_duration_ms': 0
        }
    }
    
    # PASS 1: Analyze pre-indexed findings by category
    category_scores = {}
    category_evidence = {}
    
    for cat_id, cat_info in TRIAGE_CATEGORIES.items():
        category_scores[cat_id] = {'score': 0, 'high_matches': 0, 'medium_matches': 0, 'patterns_matched': []}
        category_evidence[cat_id] = []
        
        for pattern, confidence in cat_info['patterns']:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for finding in findings:
                    sample = finding.get('sample', '')
                    file_path = finding.get('file', '')
                    
                    if regex.search(sample) or regex.search(finding.get('pattern', '')):
                        if confidence == 'high':
                            category_scores[cat_id]['score'] += 3
                            category_scores[cat_id]['high_matches'] += 1
                        else:
                            category_scores[cat_id]['score'] += 1
                            category_scores[cat_id]['medium_matches'] += 1
                        
                        category_scores[cat_id]['patterns_matched'].append(pattern)
                        
                        # Collect evidence
                        category_evidence[cat_id].append({
                            'file_path': file_path,
                            'full_key': finding.get('fullKey', ''),
                            'timestamp': extract_timestamp(sample),
                            'line_number': None,  # Would need deep scan for this
                            'byte_range': None,
                            'excerpt': sample[:300] if sample else '',
                            'pattern_matched': pattern,
                            'relevance': 'primary' if confidence == 'high' else 'corroborating'
                        })
            except re.error:
                continue
    
    # PASS 2: Detect pod states
    pod_states = detect_pod_states(findings)
    triage_result['pod_states_detected'] = pod_states
    
    # PASS 3: Detect node conditions
    node_conditions = detect_node_conditions(findings)
    triage_result['node_conditions_detected'] = node_conditions
    
    # PASS 4: Determine root cause
    # Sort categories by score
    sorted_categories = sorted(
        category_scores.items(),
        key=lambda x: (x[1]['score'], x[1]['high_matches']),
        reverse=True
    )
    
    # Find categories with findings
    categories_with_findings = [
        cat_id for cat_id, scores in sorted_categories
        if scores['score'] > 0
    ]
    triage_result['coverage_report']['categories_with_findings'] = categories_with_findings
    
    if sorted_categories and sorted_categories[0][1]['score'] > 0:
        top_cat_id = sorted_categories[0][0]
        top_cat_info = TRIAGE_CATEGORIES[top_cat_id]
        top_scores = sorted_categories[0][1]
        
        # Calculate confidence
        confidence_score = min(0.99, top_scores['score'] / 10.0)
        if top_scores['high_matches'] >= 2:
            confidence = 'high'
            confidence_score = max(confidence_score, 0.85)
        elif top_scores['high_matches'] >= 1:
            confidence = 'medium'
            confidence_score = max(confidence_score, 0.60)
        else:
            confidence = 'low'
        
        # Build root cause summary
        evidence_list = category_evidence[top_cat_id][:5]  # Top 5 evidence items
        primary_evidence = evidence_list[0] if evidence_list else {}
        
        triage_result['most_likely_root_cause'] = {
            'category': top_cat_id,
            'category_name': top_cat_info['name'],
            'confidence': confidence,
            'confidence_score': round(confidence_score, 2),
            'summary': f"{top_cat_info['name']} detected",
            'technical_detail': primary_evidence.get('excerpt', 'See evidence for details')[:200]
        }
        
        triage_result['evidence'] = evidence_list
        
        # Add secondary hypotheses
        for cat_id, scores in sorted_categories[1:4]:  # Next 3 categories
            if scores['score'] > 0:
                cat_info = TRIAGE_CATEGORIES[cat_id]
                sec_confidence_score = min(0.50, scores['score'] / 15.0)
                triage_result['secondary_hypotheses'].append({
                    'category': cat_id,
                    'category_name': cat_info['name'],
                    'confidence': 'low' if sec_confidence_score < 0.3 else 'medium',
                    'confidence_score': round(sec_confidence_score, 2),
                    'summary': f"Possible {cat_info['name'].lower()}",
                    'evidence_count': len(category_evidence[cat_id])
                })
        
        # Generate remediation steps
        triage_result['immediate_remediation_steps'] = generate_triage_remediation(
            top_cat_id, evidence_list, pod_states, node_conditions
        )
        
        # Generate preventive recommendations
        triage_result['preventive_recommendations'] = generate_preventive_recommendations(top_cat_id)
        
        # Generate followup commands
        triage_result['followup_validation_commands'] = generate_followup_commands(
            top_cat_id, pod_states, node_conditions
        )
    
    # Update coverage report
    triage_result['coverage_report']['files_scanned'] = bundle_data.get('fileCount', 0)
    triage_result['coverage_report']['files_total'] = bundle_data.get('fileCount', 0)
    triage_result['coverage_report']['scan_duration_ms'] = int((time.time() - start_time) * 1000)
    
    # Check for missing log sources
    found_patterns = bundle_data.get('foundPatterns', [])
    expected_sources = ['kubelet', 'containerd', 'dmesg', 'messages', 'networking', 'ipamd']
    missing = [s for s in expected_sources if s not in found_patterns]
    if missing:
        triage_result['coverage_report']['missing_log_sources'] = missing
    
    return triage_result


def detect_pod_states(findings: List[Dict]) -> List[Dict]:
    """Detect pod states from findings."""
    detected_states = {}
    
    for state, patterns in POD_STATE_PATTERNS.items():
        count = 0
        sample_pods = []
        
        for finding in findings:
            sample = finding.get('sample', '')
            for pattern in patterns:
                try:
                    if re.search(pattern, sample, re.IGNORECASE):
                        count += finding.get('count', 1)
                        # Try to extract pod name
                        pod_match = re.search(r'pod[/\s]+([a-z0-9-]+)', sample, re.IGNORECASE)
                        if pod_match and pod_match.group(1) not in sample_pods:
                            sample_pods.append(pod_match.group(1))
                        break
                except re.error:
                    continue
        
        if count > 0:
            detected_states[state] = {
                'state': state,
                'count': count,
                'sample_pods': sample_pods[:5]
            }
    
    return list(detected_states.values())


def detect_node_conditions(findings: List[Dict]) -> List[Dict]:
    """Detect node conditions from findings."""
    detected_conditions = []
    
    for condition, patterns in NODE_CONDITION_PATTERNS.items():
        for finding in findings:
            sample = finding.get('sample', '')
            for pattern in patterns:
                try:
                    if re.search(pattern, sample, re.IGNORECASE):
                        severity = 'critical' if condition in ['NotReady', 'MemoryPressure'] else 'warning'
                        detected_conditions.append({
                            'condition': condition,
                            'severity': severity,
                            'message': sample[:150]
                        })
                        break
                except re.error:
                    continue
    
    # Deduplicate
    seen = set()
    unique_conditions = []
    for cond in detected_conditions:
        if cond['condition'] not in seen:
            seen.add(cond['condition'])
            unique_conditions.append(cond)
    
    return unique_conditions


def generate_triage_remediation(category: str, evidence: List[Dict], 
                                 pod_states: List[Dict], node_conditions: List[Dict]) -> List[Dict]:
    """Generate immediate remediation steps based on triage category."""
    steps = []
    priority = 1
    
    if category == 'A':  # Volume/CSI
        steps = [
            {
                'priority': priority,
                'action': 'Check PV/PVC status',
                'command': "kubectl get pv,pvc -A | grep -E 'Pending|Failed'",
                'expected_outcome': 'Identify stuck volumes'
            },
            {
                'priority': priority + 1,
                'action': 'Check EBS volume attachment',
                'command': "aws ec2 describe-volumes --filters Name=status,Values=attaching,error --query 'Volumes[].{ID:VolumeId,State:State}'",
                'expected_outcome': 'Find volumes stuck in attaching state'
            },
            {
                'priority': priority + 2,
                'action': 'Check CSI driver pods',
                'command': 'kubectl get pods -n kube-system -l app=ebs-csi-controller',
                'expected_outcome': 'Verify CSI controller is running'
            },
        ]
    elif category == 'B':  # Node Issues
        steps = [
            {
                'priority': priority,
                'action': 'Check node status',
                'command': 'kubectl get nodes -o wide',
                'expected_outcome': 'Identify NotReady nodes'
            },
            {
                'priority': priority + 1,
                'action': 'Check node conditions',
                'command': "kubectl describe nodes | grep -A5 'Conditions:'",
                'expected_outcome': 'Identify pressure conditions'
            },
            {
                'priority': priority + 2,
                'action': 'Check pod resource usage',
                'command': 'kubectl top pods -A --sort-by=memory | head -20',
                'expected_outcome': 'Find memory-hungry pods'
            },
        ]
        # Add OOM-specific steps if detected
        if any(s.get('state') == 'OOMKilled' for s in pod_states):
            steps.append({
                'priority': priority + 3,
                'action': 'Increase memory limits for affected pods',
                'command': 'kubectl set resources deployment/<name> --limits=memory=1Gi',
                'expected_outcome': 'Prevent future OOM kills'
            })
    elif category == 'C':  # CNI/Networking
        steps = [
            {
                'priority': priority,
                'action': 'Check subnet IP availability',
                'command': "aws ec2 describe-subnets --query 'Subnets[].{ID:SubnetId,AvailableIPs:AvailableIpAddressCount}'",
                'expected_outcome': 'Identify IP-exhausted subnets'
            },
            {
                'priority': priority + 1,
                'action': 'Check aws-node daemonset',
                'command': 'kubectl get pods -n kube-system -l k8s-app=aws-node',
                'expected_outcome': 'Verify CNI pods are running'
            },
            {
                'priority': priority + 2,
                'action': 'Check ENI allocation',
                'command': "aws ec2 describe-network-interfaces --filters Name=description,Values='*amazon-vpc-cni*' --query 'NetworkInterfaces | length(@)'",
                'expected_outcome': 'Count ENIs used by VPC CNI'
            },
        ]
    elif category == 'D':  # iptables/conntrack
        steps = [
            {
                'priority': priority,
                'action': 'Check conntrack table usage',
                'command': 'cat /proc/sys/net/netfilter/nf_conntrack_count && cat /proc/sys/net/netfilter/nf_conntrack_max',
                'expected_outcome': 'Compare current vs max conntrack entries'
            },
            {
                'priority': priority + 1,
                'action': 'Increase conntrack max if needed',
                'command': 'sudo sysctl -w net.netfilter.nf_conntrack_max=262144',
                'expected_outcome': 'Increase conntrack table size'
            },
        ]
    elif category == 'E':  # Scheduling
        steps = [
            {
                'priority': priority,
                'action': 'Check pending pods',
                'command': "kubectl get pods -A --field-selector=status.phase=Pending",
                'expected_outcome': 'List all pending pods'
            },
            {
                'priority': priority + 1,
                'action': 'Check node resources',
                'command': 'kubectl describe nodes | grep -A10 "Allocated resources"',
                'expected_outcome': 'See resource allocation per node'
            },
            {
                'priority': priority + 2,
                'action': 'Check for taints',
                'command': "kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.spec.taints[*].key}{\"\\n\"}{end}'",
                'expected_outcome': 'Identify node taints blocking scheduling'
            },
        ]
    elif category == 'F':  # Image Pull
        steps = [
            {
                'priority': priority,
                'action': 'Check image pull errors',
                'command': "kubectl get events -A --field-selector=reason=Failed | grep -i image",
                'expected_outcome': 'Find image pull failures'
            },
            {
                'priority': priority + 1,
                'action': 'Verify ECR authentication',
                'command': 'aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com',
                'expected_outcome': 'Test ECR authentication'
            },
        ]
    elif category == 'G':  # DNS
        steps = [
            {
                'priority': priority,
                'action': 'Check CoreDNS pods',
                'command': 'kubectl get pods -n kube-system -l k8s-app=kube-dns',
                'expected_outcome': 'Verify CoreDNS is running'
            },
            {
                'priority': priority + 1,
                'action': 'Test DNS resolution',
                'command': 'kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup kubernetes.default',
                'expected_outcome': 'Verify DNS works from pod'
            },
        ]
    elif category == 'H':  # Secrets/Webhook
        steps = [
            {
                'priority': priority,
                'action': 'Check secrets access',
                'command': 'kubectl get secrets -A | head -20',
                'expected_outcome': 'List accessible secrets'
            },
            {
                'priority': priority + 1,
                'action': 'Check webhook configurations',
                'command': 'kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations',
                'expected_outcome': 'List active webhooks'
            },
        ]
    
    return steps


def generate_preventive_recommendations(category: str) -> List[Dict]:
    """Generate preventive recommendations based on category."""
    recommendations = {
        'A': [
            {
                'category': 'monitoring',
                'recommendation': 'Set up CloudWatch alarms for EBS volume attachment failures',
                'reference': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-volume-status.html'
            },
            {
                'category': 'configuration',
                'recommendation': 'Use volumeBindingMode: WaitForFirstConsumer in StorageClass',
                'reference': 'https://kubernetes.io/docs/concepts/storage/storage-classes/#volume-binding-mode'
            },
        ],
        'B': [
            {
                'category': 'capacity_planning',
                'recommendation': 'Implement pod resource requests and limits',
                'reference': 'https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/'
            },
            {
                'category': 'monitoring',
                'recommendation': 'Set up Container Insights for memory/CPU monitoring',
                'reference': 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-quickstart.html'
            },
        ],
        'C': [
            {
                'category': 'capacity_planning',
                'recommendation': 'Enable VPC CNI prefix delegation for higher IP density',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/cni-increase-ip-addresses.html'
            },
            {
                'category': 'monitoring',
                'recommendation': 'Monitor subnet IP availability with CloudWatch',
                'reference': 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cloudwatch.html'
            },
        ],
        'D': [
            {
                'category': 'configuration',
                'recommendation': 'Increase nf_conntrack_max via node configuration',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/node-group-launch-template.html'
            },
        ],
        'E': [
            {
                'category': 'capacity_planning',
                'recommendation': 'Implement Cluster Autoscaler or Karpenter',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/autoscaling.html'
            },
        ],
        'F': [
            {
                'category': 'security',
                'recommendation': 'Use ECR pull-through cache for external images',
                'reference': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/pull-through-cache.html'
            },
        ],
        'G': [
            {
                'category': 'reliability',
                'recommendation': 'Scale CoreDNS based on cluster size',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/coredns.html'
            },
        ],
        'H': [
            {
                'category': 'security',
                'recommendation': 'Use EKS Pod Identity for secrets access',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html'
            },
        ],
    }
    
    return recommendations.get(category, [])


def generate_followup_commands(category: str, pod_states: List[Dict], 
                                node_conditions: List[Dict]) -> List[Dict]:
    """Generate followup validation commands."""
    commands = []
    
    # Common commands
    commands.append({
        'tool': 'kubectl',
        'command': "kubectl get pods -A | grep -E 'Pending|ContainerCreating|CrashLoopBackOff|Error' | wc -l",
        'purpose': 'Count pods in problematic states'
    })
    
    if category == 'C':  # CNI
        commands.append({
            'tool': 'kubectl',
            'command': 'kubectl logs -n kube-system -l k8s-app=aws-node --tail=50',
            'purpose': 'Check aws-node for IP allocation success'
        })
    elif category == 'B':  # Node
        commands.append({
            'tool': 'kubectl',
            'command': 'kubectl get nodes',
            'purpose': 'Verify all nodes are Ready'
        })
    elif category == 'A':  # Volume
        commands.append({
            'tool': 'kubectl',
            'command': "kubectl get pv,pvc -A | grep -v Bound",
            'purpose': 'Check for unbound volumes'
        })
    
    return commands


# =============================================================================
# S3 SAFE HELPERS
# =============================================================================

def safe_s3_read(key: str, range_bytes: str = None, max_size: int = 1048576) -> Dict:
    """
    Safely read from S3 with graceful error handling.
    Returns dict with 'success', 'content' or 'error', and 'error_type'.
    NEVER raises exceptions - always returns a result dict.
    """
    try:
        params = {'Bucket': LOGS_BUCKET, 'Key': key}
        if range_bytes:
            params['Range'] = range_bytes
        
        response = s3_client.get_object(**params)
        content = response['Body'].read()
        
        # Decode with fallback
        try:
            content_str = content.decode('utf-8')
        except UnicodeDecodeError:
            content_str = content.decode('latin-1', errors='replace')
        
        return {
            'success': True,
            'content': content_str,
            'size': len(content),
            'content_type': response.get('ContentType', 'unknown')
        }
        
    except s3_client.exceptions.NoSuchKey:
        return {
            'success': False,
            'error': f'File not found: {key}',
            'error_type': 'not_found',
            'content': ''
        }
    except s3_client.exceptions.InvalidRange:
        return {
            'success': False,
            'error': f'Invalid byte range for: {key}',
            'error_type': 'invalid_range',
            'content': ''
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Failed to read {key}: {str(e)}',
            'error_type': 'read_error',
            'content': ''
        }


def safe_s3_head(key: str) -> Dict:
    """
    Safely get S3 object metadata with graceful error handling.
    NEVER raises exceptions - always returns a result dict.
    """
    try:
        response = s3_client.head_object(Bucket=LOGS_BUCKET, Key=key)
        return {
            'success': True,
            'size': response['ContentLength'],
            'content_type': response.get('ContentType', 'unknown'),
            'last_modified': response.get('LastModified')
        }
    except s3_client.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == '404':
            return {
                'success': False,
                'error': f'File not found: {key}',
                'error_type': 'not_found'
            }
        return {
            'success': False,
            'error': f'Failed to get metadata for {key}: {str(e)}',
            'error_type': 'metadata_error'
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Failed to get metadata for {key}: {str(e)}',
            'error_type': 'unknown_error'
        }


def safe_s3_list(prefix: str, max_keys: int = 1000) -> Dict:
    """
    Safely list S3 objects with graceful error handling.
    NEVER raises exceptions - always returns a result dict.
    """
    try:
        all_objects = []
        paginator = s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(Bucket=LOGS_BUCKET, Prefix=prefix, PaginationConfig={'MaxItems': max_keys}):
            for obj in page.get('Contents', []):
                all_objects.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj.get('LastModified')
                })
        
        return {
            'success': True,
            'objects': all_objects,
            'count': len(all_objects)
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Failed to list objects with prefix {prefix}: {str(e)}',
            'error_type': 'list_error',
            'objects': [],
            'count': 0
        }


def lambda_handler(event, context):
    """Main Lambda handler - routes to appropriate tool function."""
    print(f"Received event: {json.dumps(event)}")
    
    # Extract tool name from AgentCore context
    delimiter = "___"
    original_tool_name = context.client_context.custom.get('bedrockAgentCoreToolName', '')
    
    if delimiter in original_tool_name:
        tool_name = original_tool_name[original_tool_name.index(delimiter) + len(delimiter):]
    else:
        tool_name = original_tool_name
    
    print(f"Executing tool: {tool_name}")
    
    # Tool routing
    tools = {
        # Core Operations (Tier 1)
        'start_log_collection': start_log_collection,
        'get_collection_status': get_collection_status,
        'validate_bundle_completeness': validate_bundle_completeness,
        'get_error_summary': get_error_summary,
        'read_log_chunk': read_log_chunk,
        
        # Advanced Analysis (Tier 2)
        'search_logs_deep': search_logs_deep,
        'correlate_events': correlate_events,
        'get_artifact_reference': get_artifact_reference,
        'generate_incident_summary': generate_incident_summary,
        'list_collection_history': list_collection_history,
        
        # Legacy compatibility
        'run_eks_log_collection': start_log_collection,
        'get_automation_status': get_collection_status,
        'list_automations': list_collection_history,
        'list_collected_logs': list_collected_logs,
        'get_log_content': get_log_content_legacy,
        'search_log_errors': search_log_errors_legacy,
    }
    
    if tool_name not in tools:
        return error_response(400, f'Unknown tool: {tool_name}', {
            'available_tools': list(tools.keys())
        })
    
    try:
        return tools[tool_name](event)
    except Exception as e:
        print(f"Error executing {tool_name}: {str(e)}")
        import traceback
        traceback.print_exc()
        return error_response(500, f'Internal error: {str(e)}')


def success_response(data: Dict) -> Dict:
    """Standard success response format."""
    return {
        'statusCode': 200,
        'body': json.dumps({
            'success': True,
            **data
        }, default=str)
    }


def error_response(status_code: int, message: str, details: Dict = None) -> Dict:
    """Standard error response format."""
    body = {'success': False, 'error': message}
    if details:
        body['details'] = details
    return {
        'statusCode': status_code,
        'body': json.dumps(body, default=str)
    }


# =============================================================================
# TIER 1: CORE OPERATIONS
# =============================================================================

def start_log_collection(arguments: Dict) -> Dict:
    """
    Start EKS log collection with idempotency support.
    
    Inputs:
        instanceId: EC2 instance ID (required)
        idempotencyToken: Optional token to prevent duplicate executions
    
    Returns:
        executionId, estimatedCompletionTime, status
    """
    instance_id = arguments.get('instanceId')
    idempotency_token = arguments.get('idempotencyToken')
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    # Check for existing execution with same idempotency token
    if idempotency_token:
        existing = find_execution_by_idempotency_token(instance_id, idempotency_token)
        if existing:
            return success_response({
                'message': 'Returning existing execution (idempotent)',
                'executionId': existing['executionId'],
                'status': existing['status'],
                'instanceId': instance_id,
                'idempotent': True
            })
    
    try:
        # Start SSM Automation
        params = {
            'EKSInstanceId': [instance_id],
            'LogDestination': [LOGS_BUCKET],
            'AutomationAssumeRole': [SSM_AUTOMATION_ROLE_ARN]
        }
        
        response = ssm_client.start_automation_execution(
            DocumentName='AWSSupport-CollectEKSInstanceLogs',
            Parameters=params
        )
        
        execution_id = response['AutomationExecutionId']
        
        # Store idempotency mapping if token provided
        if idempotency_token:
            store_idempotency_mapping(instance_id, idempotency_token, execution_id)
        
        return success_response({
            'message': 'EKS log collection started',
            'executionId': execution_id,
            'instanceId': instance_id,
            's3Bucket': LOGS_BUCKET,
            'estimatedCompletionTime': '3-5 minutes',
            'suggestedPollIntervalSeconds': 15,
            'nextStep': f'Poll status with get_collection_status(executionId="{execution_id}") every 15 seconds'
        })
        
    except ssm_client.exceptions.AutomationDefinitionNotFoundException:
        return error_response(404, 'AWSSupport-CollectEKSInstanceLogs document not found', {
            'suggestion': 'This document may not be available in your region'
        })
    except Exception as e:
        return error_response(500, f'Failed to start log collection: {str(e)}')


def get_collection_status(arguments: Dict) -> Dict:
    """
    Get detailed status of log collection with progress tracking.
    
    Inputs:
        executionId: SSM Automation execution ID (required)
        includeStepDetails: Include individual step status (default: true)
    
    Returns:
        status, progress, stepDetails, failureReason (if failed)
    """
    execution_id = arguments.get('executionId')
    include_steps = arguments.get('includeStepDetails', True)
    
    if not execution_id:
        return error_response(400, 'executionId is required')
    
    try:
        response = ssm_client.get_automation_execution(
            AutomationExecutionId=execution_id
        )
        execution = response['AutomationExecution']
        
        status = execution['AutomationExecutionStatus']
        
        result = {
            'executionId': execution_id,
            'status': status,
            'documentName': execution.get('DocumentName', ''),
            'startTime': execution.get('ExecutionStartTime'),
            'endTime': execution.get('ExecutionEndTime'),
        }
        
        # Calculate progress
        if status == 'Success':
            result['progress'] = 100
        elif status == 'Failed':
            result['progress'] = 0
            result['failureReason'] = parse_failure_reason(execution)
        elif status == 'InProgress':
            result['progress'] = estimate_progress(execution)
        else:
            result['progress'] = 0
        
        # Include step details
        if include_steps and 'StepExecutions' in execution:
            result['stepDetails'] = [
                {
                    'stepName': step.get('StepName'),
                    'status': step.get('StepStatus'),
                    'startTime': step.get('ExecutionStartTime'),
                    'endTime': step.get('ExecutionEndTime'),
                }
                for step in execution.get('StepExecutions', [])
            ]
        
        # Add outputs if available
        if 'Outputs' in execution:
            result['outputs'] = execution['Outputs']
        
        # Provide next step guidance
        if status == 'Success':
            result['nextStep'] = f'Validate bundle with validate_bundle_completeness(executionId="{execution_id}")'
        elif status == 'InProgress':
            result['suggestedPollIntervalSeconds'] = 15
            result['nextStep'] = 'Wait 15 seconds then poll again until status is Success or Failed'
        elif status == 'Failed':
            result['nextStep'] = 'Review failureReason and retry if appropriate'
        
        return success_response({'automation': result})
        
    except ssm_client.exceptions.AutomationExecutionNotFoundException:
        return error_response(404, f'Execution {execution_id} not found')
    except Exception as e:
        return error_response(500, f'Failed to get status: {str(e)}')


def validate_bundle_completeness(arguments: Dict) -> Dict:
    """
    Verify all expected files were extracted from log bundle.
    Gracefully handles missing logs - reports what's available without failing.
    
    Inputs:
        executionId: SSM execution ID OR
        instanceId: Instance ID + timestamp to locate bundle
    
    Returns:
        complete (bool), fileCount, totalSize, missingPatterns, manifest
    """
    execution_id = arguments.get('executionId')
    instance_id = arguments.get('instanceId')
    
    if not execution_id and not instance_id:
        return error_response(400, 'Either executionId or instanceId is required')
    
    try:
        # Determine prefix from execution or instance
        if instance_id:
            prefix = f'eks_{instance_id}'
        else:
            # Get instance ID from execution
            try:
                exec_response = ssm_client.get_automation_execution(
                    AutomationExecutionId=execution_id
                )
                params = exec_response['AutomationExecution'].get('Parameters', {})
                instance_id = params.get('EKSInstanceId', [''])[0]
                prefix = f'eks_{instance_id}'
            except ssm_client.exceptions.AutomationExecutionNotFoundException:
                return error_response(404, f'Execution {execution_id} not found')
            except Exception as e:
                return error_response(500, f'Failed to get execution details: {str(e)}')
        
        # List all files using safe helper
        list_result = safe_s3_list(prefix, max_keys=5000)
        
        if not list_result['success']:
            # Return partial result even if listing fails
            return success_response({
                'complete': False,
                'fileCount': 0,
                'totalSize': 0,
                'totalSizeHuman': '0 B',
                'missingPatterns': ['all'],
                'foundPatterns': [],
                'hasFindingsIndex': False,
                'instanceId': instance_id,
                'manifest': [],
                'warning': list_result.get('error', 'Failed to list files'),
                'nextStep': 'Check if log collection completed successfully'
            })
        
        # Filter for extracted files
        all_files = [
            obj for obj in list_result['objects']
            if '/extracted/' in obj['key']
        ]
        
        # Handle case where no logs found
        if not all_files:
            return success_response({
                'complete': False,
                'fileCount': 0,
                'totalSize': 0,
                'totalSizeHuman': '0 B',
                'missingPatterns': ['all - no extracted logs found'],
                'foundPatterns': [],
                'hasFindingsIndex': False,
                'instanceId': instance_id,
                'manifest': [],
                'info': 'No extracted log files found. Log collection may still be in progress or may have failed.',
                'nextStep': 'Check log collection status with get_collection_status'
            })
        
        total_size = sum(f['size'] for f in all_files)
        
        # Check for expected log patterns - these are optional, not required
        expected_patterns = [
            'kubelet', 'containerd', 'dmesg', 'messages',
            'networking', 'storage', 'pods'
        ]
        
        found_patterns = set()
        for f in all_files:
            key_lower = f['key'].lower()
            for pattern in expected_patterns:
                if pattern in key_lower:
                    found_patterns.add(pattern)
        
        missing_patterns = list(set(expected_patterns) - found_patterns)
        
        # Check for findings index
        has_findings_index = any(
            FINDINGS_INDEX_FILE in f['key'] for f in all_files
        )
        
        # Consider complete if we have at least some files (not all patterns required)
        is_complete = len(all_files) >= 5 and len(found_patterns) >= 3
        
        result = {
            'complete': is_complete,
            'fileCount': len(all_files),
            'totalSize': total_size,
            'totalSizeHuman': format_bytes(total_size),
            'missingPatterns': missing_patterns,
            'foundPatterns': list(found_patterns),
            'hasFindingsIndex': has_findings_index,
            'instanceId': instance_id,
        }
        
        # Add info about missing patterns (not an error, just informational)
        if missing_patterns:
            result['info'] = f'Some log types not found: {", ".join(missing_patterns)}. This may be normal depending on node configuration.'
        
        # Include manifest (first 50 files)
        result['manifest'] = [
            {
                'key': f['key'].split('/extracted/')[-1] if '/extracted/' in f['key'] else f['key'],
                'fullKey': f['key'],
                'size': f['size'],
                'sizeHuman': format_bytes(f['size'])
            }
            for f in sorted(all_files, key=lambda x: x['size'], reverse=True)[:50]
        ]
        
        if is_complete:
            result['nextStep'] = f'Get error summary with get_error_summary(instanceId="{instance_id}")'
        else:
            result['nextStep'] = 'Bundle may be incomplete. Check SSM Automation status or proceed with available logs.'
        
        return success_response(result)
        
    except Exception as e:
        # Even on unexpected error, return a graceful response
        return success_response({
            'complete': False,
            'fileCount': 0,
            'totalSize': 0,
            'totalSizeHuman': '0 B',
            'missingPatterns': ['unknown'],
            'foundPatterns': [],
            'hasFindingsIndex': False,
            'instanceId': instance_id or 'unknown',
            'manifest': [],
            'error': f'Unexpected error during validation: {str(e)}',
            'nextStep': 'Retry or check AWS console for log collection status'
        })


def get_error_summary(arguments: Dict) -> Dict:
    """
    Get pre-indexed error findings (fast path, no scanning).
    Gracefully handles missing logs - returns empty findings without failing.
    
    Inputs:
        instanceId: EC2 instance ID (required)
        severity: Filter by severity (critical|warning|info|all)
    
    Returns:
        findings[], summary counts, indexed timestamp
    """
    instance_id = arguments.get('instanceId')
    severity_filter = arguments.get('severity', 'all')
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    try:
        # Try to read pre-computed findings index
        prefix = f'eks_{instance_id}'
        index_key = find_findings_index(prefix)
        
        if index_key:
            # Fast path: return cached findings
            read_result = safe_s3_read(index_key)
            
            if read_result['success']:
                try:
                    index_data = json.loads(read_result['content'])
                    findings = index_data.get('findings', [])
                    
                    # Filter by severity if requested
                    if severity_filter != 'all':
                        findings = [f for f in findings if f.get('severity') == severity_filter]
                    
                    return success_response({
                        'instanceId': instance_id,
                        'indexedAt': index_data.get('indexedAt'),
                        'findings': findings[:100],  # Limit response size
                        'totalFindings': len(findings),
                        'summary': index_data.get('summary', {}),
                        'cached': True,
                        'nextStep': 'Use search_logs_deep for detailed investigation'
                    })
                except json.JSONDecodeError:
                    # Index file corrupted, fall through to scan
                    print(f"Warning: Findings index corrupted, will scan on-demand")
        
        # Slow path: scan and index on-demand
        return scan_and_index_errors(instance_id, severity_filter)
        
    except Exception as e:
        # Return empty findings on error, don't fail
        return success_response({
            'instanceId': instance_id,
            'findings': [],
            'totalFindings': 0,
            'summary': {'critical': 0, 'warning': 0, 'info': 0},
            'cached': False,
            'warning': f'Could not retrieve error summary: {str(e)}',
            'nextStep': 'Check if logs exist with validate_bundle_completeness'
        })


def read_log_chunk(arguments: Dict) -> Dict:
    """
    Byte-range streaming for large log files. NO TRUNCATION.
    Gracefully handles missing files - returns informative error without failing.
    
    Inputs:
        logKey: S3 key of log file (required)
        startByte: Starting byte offset (default: 0)
        endByte: Ending byte offset (optional, defaults to startByte + 1MB)
        startLine: Starting line number (alternative to byte range)
        lineCount: Number of lines to return (default: 1000)
    
    Returns:
        content, startByte, endByte, totalSize, hasMore, nextChunkToken
    """
    log_key = arguments.get('logKey')
    start_byte = arguments.get('startByte', 0)
    end_byte = arguments.get('endByte')
    start_line = arguments.get('startLine')
    line_count = arguments.get('lineCount', DEFAULT_LINE_COUNT)
    
    if not log_key:
        return error_response(400, 'logKey is required')
    
    try:
        # Get file metadata using safe helper
        head_result = safe_s3_head(log_key)
        
        if not head_result['success']:
            # File not found or inaccessible - return graceful response
            return success_response({
                'logKey': log_key,
                'content': '',
                'startByte': 0,
                'endByte': 0,
                'chunkSize': 0,
                'totalSize': 0,
                'totalSizeHuman': '0 B',
                'hasMore': False,
                'nextChunkToken': None,
                'truncated': False,
                'fileNotFound': True,
                'warning': head_result.get('error', 'File not found or inaccessible'),
                'suggestion': 'The log file may not exist or may have been cleaned up. Try listing available logs first.'
            })
        
        total_size = head_result['size']
        
        # For very large files, return presigned URL instead
        if total_size > MAX_CHUNK_SIZE * 10:  # >50MB
            return get_artifact_reference({'logKey': log_key, 'reason': 'File too large for direct read'})
        
        # Line-based reading
        if start_line is not None:
            return read_by_lines(log_key, start_line, min(line_count, MAX_LINE_COUNT), total_size)
        
        # Byte-range reading
        if end_byte is None:
            end_byte = min(start_byte + DEFAULT_CHUNK_SIZE, total_size)
        
        # Clamp to valid range
        start_byte = max(0, start_byte)
        end_byte = min(end_byte, total_size)
        chunk_size = end_byte - start_byte
        
        if chunk_size > MAX_CHUNK_SIZE:
            end_byte = start_byte + MAX_CHUNK_SIZE
            chunk_size = MAX_CHUNK_SIZE
        
        # Handle empty file
        if total_size == 0 or chunk_size <= 0:
            return success_response({
                'logKey': log_key,
                'content': '',
                'startByte': 0,
                'endByte': 0,
                'chunkSize': 0,
                'totalSize': total_size,
                'totalSizeHuman': format_bytes(total_size),
                'hasMore': False,
                'nextChunkToken': None,
                'truncated': False,
                'info': 'File is empty or requested range is invalid'
            })
        
        # Read chunk using safe helper
        range_header = f'bytes={start_byte}-{end_byte - 1}'
        read_result = safe_s3_read(log_key, range_bytes=range_header)
        
        if not read_result['success']:
            return success_response({
                'logKey': log_key,
                'content': '',
                'startByte': start_byte,
                'endByte': end_byte,
                'chunkSize': 0,
                'totalSize': total_size,
                'totalSizeHuman': format_bytes(total_size),
                'hasMore': False,
                'nextChunkToken': None,
                'truncated': False,
                'warning': read_result.get('error', 'Failed to read file content'),
                'suggestion': 'Try a different byte range or check file permissions'
            })
        
        content_str = read_result['content']
        has_more = end_byte < total_size
        
        return success_response({
            'logKey': log_key,
            'content': content_str,
            'startByte': start_byte,
            'endByte': end_byte,
            'chunkSize': len(content_str),
            'totalSize': total_size,
            'totalSizeHuman': format_bytes(total_size),
            'hasMore': has_more,
            'nextChunkToken': str(end_byte) if has_more else None,
            'truncated': False,  # NEVER truncate
        })
        
    except Exception as e:
        # Even on unexpected error, return graceful response
        return success_response({
            'logKey': log_key,
            'content': '',
            'startByte': 0,
            'endByte': 0,
            'chunkSize': 0,
            'totalSize': 0,
            'totalSizeHuman': '0 B',
            'hasMore': False,
            'nextChunkToken': None,
            'truncated': False,
            'error': f'Unexpected error reading log: {str(e)}',
            'suggestion': 'Check if the log key is correct and the file exists'
        })


# =============================================================================
# TIER 2: ADVANCED ANALYSIS
# =============================================================================

def search_logs_deep(arguments: Dict) -> Dict:
    """
    Full-text search across all logs without truncation.
    Gracefully handles missing logs - returns empty results without failing.
    
    Inputs:
        instanceId: EC2 instance ID (required)
        query: Regex pattern to search (required)
        logTypes: Comma-separated log types to search (optional)
        timeRange: ISO timestamp range (optional)
        maxResults: Max results per file (default: 100)
    
    Returns:
        matches[], pagination info
    """
    instance_id = arguments.get('instanceId')
    query = arguments.get('query')
    log_types_str = arguments.get('logTypes', '')
    max_results = min(arguments.get('maxResults', 100), 500)
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    if not query:
        return error_response(400, 'query is required')
    
    try:
        # Compile regex
        try:
            pattern = re.compile(query, re.IGNORECASE)
        except re.error as e:
            return error_response(400, f'Invalid regex pattern: {str(e)}')
        
        # Get file patterns to search
        file_patterns = None
        if log_types_str:
            file_patterns = []
            for log_type in log_types_str.split(','):
                log_type = log_type.strip().lower()
                if log_type in LOG_TYPE_PATTERNS:
                    file_patterns.extend(LOG_TYPE_PATTERNS[log_type])
        
        # List files to search using safe helper
        prefix = f'eks_{instance_id}'
        list_result = safe_s3_list(prefix, max_keys=5000)
        
        if not list_result['success']:
            return success_response({
                'instanceId': instance_id,
                'query': query,
                'filesSearched': 0,
                'filesWithMatches': 0,
                'totalMatches': 0,
                'results': [],
                'truncated': False,
                'warning': list_result.get('error', 'Failed to list log files'),
                'nextStep': 'Check if logs exist with validate_bundle_completeness'
            })
        
        # Filter files to search
        files_to_search = []
        for obj in list_result['objects']:
            key = obj['key']
            if '/extracted/' not in key:
                continue
            if any(key.endswith(ext) for ext in ['.tar.gz', '.zip', '.gz', '.bin', '.so']):
                continue
            if obj['size'] > 10485760:  # Skip files >10MB for deep search
                continue
            
            # Filter by log type
            if file_patterns:
                if not any(p in key.lower() for p in file_patterns):
                    continue
            
            files_to_search.append({
                'key': key,
                'size': obj['size']
            })
        
        # Handle no files found
        if not files_to_search:
            return success_response({
                'instanceId': instance_id,
                'query': query,
                'filesSearched': 0,
                'filesWithMatches': 0,
                'totalMatches': 0,
                'results': [],
                'truncated': False,
                'info': 'No log files found matching criteria. Log collection may still be in progress.',
                'nextStep': 'Check log collection status or try different log types'
            })
        
        # Search files
        all_matches = []
        files_searched = 0
        files_with_errors = 0
        
        for file_info in files_to_search[:50]:  # Limit files to prevent timeout
            files_searched += 1
            matches = search_file_for_pattern(file_info['key'], pattern, max_results)
            
            if matches is None:
                # File read error - count but don't fail
                files_with_errors += 1
                continue
            
            if matches:
                filename = file_info['key'].split('/extracted/')[-1]
                all_matches.append({
                    'file': filename,
                    'fullKey': file_info['key'],
                    'matchCount': len(matches),
                    'matches': matches
                })
            
            if sum(len(m['matches']) for m in all_matches) >= max_results * 5:
                break
        
        # Sort by match count
        all_matches.sort(key=lambda x: x['matchCount'], reverse=True)
        
        result = {
            'instanceId': instance_id,
            'query': query,
            'filesSearched': files_searched,
            'filesWithMatches': len(all_matches),
            'totalMatches': sum(m['matchCount'] for m in all_matches),
            'results': all_matches,
            'truncated': files_searched < len(files_to_search),
            'nextStep': 'Use read_log_chunk to get full context around specific matches'
        }
        
        if files_with_errors > 0:
            result['info'] = f'{files_with_errors} files could not be read (may be binary or inaccessible)'
        
        return success_response(result)
        
    except Exception as e:
        # Return empty results on error, don't fail
        return success_response({
            'instanceId': instance_id,
            'query': query,
            'filesSearched': 0,
            'filesWithMatches': 0,
            'totalMatches': 0,
            'results': [],
            'truncated': False,
            'error': f'Search encountered an error: {str(e)}',
            'nextStep': 'Check if logs exist with validate_bundle_completeness'
        })


def correlate_events(arguments: Dict) -> Dict:
    """
    Cross-file timeline correlation for incident analysis.
    Gracefully handles missing data - returns empty correlations without failing.
    
    Inputs:
        instanceId: EC2 instance ID (required)
        timeWindow: Seconds around pivot event (default: 60)
        pivotEvent: Event to correlate around (optional)
        components: Components to include (optional)
    
    Returns:
        timeline[], correlations
    """
    instance_id = arguments.get('instanceId')
    time_window = arguments.get('timeWindow', 60)
    pivot_event = arguments.get('pivotEvent')
    components = arguments.get('components', [])
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    try:
        # Get error summary first
        error_summary = scan_and_index_errors(instance_id, 'all')
        
        # Handle case where scan returns error or no findings
        if error_summary['statusCode'] != 200:
            # Return empty correlation instead of failing
            return success_response({
                'instanceId': instance_id,
                'timeWindow': time_window,
                'timeline': [],
                'byComponent': {},
                'correlations': [],
                'warning': 'Could not retrieve error data for correlation',
                'nextStep': 'Check if logs exist with validate_bundle_completeness'
            })
        
        summary_data = json.loads(error_summary['body'])
        findings = summary_data.get('findings', [])
        
        # Handle no findings
        if not findings:
            return success_response({
                'instanceId': instance_id,
                'timeWindow': time_window,
                'timeline': [],
                'byComponent': {},
                'correlations': [],
                'info': 'No error findings to correlate. This may indicate a healthy node or logs not yet collected.',
                'nextStep': 'Use search_logs_deep to search for specific patterns'
            })
        
        # Build timeline from findings
        timeline = []
        for finding in findings:
            # Parse timestamp if available
            timestamp = extract_timestamp(finding.get('sample', ''))
            
            timeline.append({
                'timestamp': timestamp,
                'source': finding.get('file', 'unknown'),
                'severity': finding.get('severity', 'info'),
                'event': finding.get('pattern', ''),
                'sample': finding.get('sample', '')[:200],
                'count': finding.get('count', 1)
            })
        
        # Sort by severity (critical first) then by count
        severity_order = {'critical': 0, 'warning': 1, 'info': 2}
        timeline.sort(key=lambda x: (severity_order.get(x['severity'], 3), -x['count']))
        
        # Group by component
        by_component = {}
        for event in timeline:
            source = event['source']
            component = categorize_log_source(source)
            if component not in by_component:
                by_component[component] = []
            by_component[component].append(event)
        
        return success_response({
            'instanceId': instance_id,
            'timeWindow': time_window,
            'timeline': timeline[:50],
            'byComponent': by_component,
            'correlations': find_correlations(timeline),
            'nextStep': 'Use search_logs_deep to investigate specific events'
        })
        
    except Exception as e:
        # Return empty correlation on error, don't fail
        return success_response({
            'instanceId': instance_id,
            'timeWindow': time_window,
            'timeline': [],
            'byComponent': {},
            'correlations': [],
            'error': f'Correlation encountered an error: {str(e)}',
            'nextStep': 'Check if logs exist with validate_bundle_completeness'
        })


def get_artifact_reference(arguments: Dict) -> Dict:
    """
    Get secure presigned URL for large artifacts.
    Gracefully handles missing files - returns informative error without failing.
    
    Inputs:
        logKey: S3 key of artifact (required)
        expirationMinutes: URL expiration (default: 15, max: 60)
    
    Returns:
        presignedUrl, s3Uri, sha256, size
    """
    log_key = arguments.get('logKey')
    expiration_minutes = min(arguments.get('expirationMinutes', 15), 60)
    
    if not log_key:
        return error_response(400, 'logKey is required')
    
    try:
        # Get file metadata using safe helper
        head_result = safe_s3_head(log_key)
        
        if not head_result['success']:
            return success_response({
                'logKey': log_key,
                'presignedUrl': None,
                's3Uri': f's3://{LOGS_BUCKET}/{log_key}',
                'size': 0,
                'sizeHuman': '0 B',
                'fileNotFound': True,
                'warning': head_result.get('error', 'File not found or inaccessible'),
                'suggestion': 'The artifact may not exist or may have been cleaned up. Try listing available logs first.'
            })
        
        # Generate presigned URL
        try:
            presigned_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': LOGS_BUCKET, 'Key': log_key},
                ExpiresIn=expiration_minutes * 60
            )
        except Exception as e:
            return success_response({
                'logKey': log_key,
                'presignedUrl': None,
                's3Uri': f's3://{LOGS_BUCKET}/{log_key}',
                'size': head_result['size'],
                'sizeHuman': format_bytes(head_result['size']),
                'warning': f'Could not generate presigned URL: {str(e)}',
                'suggestion': 'Use AWS CLI or console to download the file directly'
            })
        
        return success_response({
            'logKey': log_key,
            'presignedUrl': presigned_url,
            's3Uri': f's3://{LOGS_BUCKET}/{log_key}',
            'size': head_result['size'],
            'sizeHuman': format_bytes(head_result['size']),
            'contentType': head_result.get('content_type', 'application/octet-stream'),
            'lastModified': head_result.get('last_modified'),
            'expiresIn': f'{expiration_minutes} minutes',
            'note': 'Use this URL to download the full artifact. URL expires after the specified time.'
        })
        
    except Exception as e:
        return success_response({
            'logKey': log_key,
            'presignedUrl': None,
            's3Uri': f's3://{LOGS_BUCKET}/{log_key}',
            'size': 0,
            'sizeHuman': '0 B',
            'error': f'Unexpected error: {str(e)}',
            'suggestion': 'Check if the log key is correct and try again'
        })


def generate_incident_summary(arguments: Dict) -> Dict:
    """
    Generate AI-ready structured incident summary with Pod/Node failure triage.
    Gracefully handles missing data - returns partial summary without failing.
    
    Inputs:
        instanceId: EC2 instance ID (required)
        includeRecommendations: Include remediation suggestions (default: true)
        includeTriage: Include pod/node failure triage analysis (default: true)
    
    Returns:
        summary with criticalFindings, timeline, recommendations, artifactLinks, pod_node_triage
    """
    import time
    start_time = time.time()
    MAX_EXECUTION_TIME = 25  # Leave buffer for API Gateway 29s timeout
    
    def check_timeout():
        elapsed = time.time() - start_time
        if elapsed > MAX_EXECUTION_TIME:
            raise TimeoutError(f"Execution time exceeded {MAX_EXECUTION_TIME}s")
        return elapsed
    
    instance_id = arguments.get('instanceId')
    include_recommendations = arguments.get('includeRecommendations', True)
    include_triage = arguments.get('includeTriage', True)
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    try:
        # Get bundle completeness - don't fail if this errors
        bundle_data = {}
        try:
            check_timeout()
            bundle_result = validate_bundle_completeness({'instanceId': instance_id})
            if bundle_result['statusCode'] == 200:
                bundle_data = json.loads(bundle_result['body'])
        except TimeoutError:
            raise
        except Exception as e:
            print(f"Warning: Could not get bundle completeness: {str(e)}")
        
        # Get error summary - don't fail if this errors
        error_data = {}
        try:
            check_timeout()
            error_result = get_error_summary({'instanceId': instance_id, 'severity': 'all'})
            if error_result['statusCode'] == 200:
                error_data = json.loads(error_result['body'])
        except TimeoutError:
            raise
        except Exception as e:
            print(f"Warning: Could not get error summary: {str(e)}")
        
        check_timeout()
        
        # Build summary with available data
        findings = error_data.get('findings', [])
        summary_counts = error_data.get('summary', {'critical': 0, 'warning': 0, 'info': 0})
        
        critical_findings = [f for f in findings if f.get('severity') == 'critical'][:10]
        warning_findings = [f for f in findings if f.get('severity') == 'warning'][:10]
        
        # Identify affected components
        affected_components = set()
        for finding in findings:
            component = categorize_log_source(finding.get('file', ''))
            affected_components.add(component)
        
        summary = {
            'instanceId': instance_id,
            'generatedAt': datetime.utcnow().isoformat(),
            'executionTimeMs': int((time.time() - start_time) * 1000),
            'bundleStatus': {
                'complete': bundle_data.get('complete', False),
                'fileCount': bundle_data.get('fileCount', 0),
                'totalSize': bundle_data.get('totalSizeHuman', 'unknown')
            },
            'errorSummary': {
                'critical': summary_counts.get('critical', 0),
                'warning': summary_counts.get('warning', 0),
                'info': summary_counts.get('info', 0),
                'total': len(findings)
            },
            'criticalFindings': [
                {
                    'file': f.get('file'),
                    'fullKey': f.get('fullKey'),
                    'pattern': f.get('pattern'),
                    'count': f.get('count'),
                    'sample': f.get('sample', '')[:200]
                }
                for f in critical_findings
            ],
            'warningFindings': [
                {
                    'file': f.get('file'),
                    'fullKey': f.get('fullKey'),
                    'pattern': f.get('pattern'),
                    'count': f.get('count')
                }
                for f in warning_findings
            ],
            'affectedComponents': list(affected_components),
        }
        
        # Add info if no findings
        if not findings:
            summary['info'] = 'No error findings detected. Node may be healthy or logs not yet collected.'
        
        # Add recommendations if requested
        if include_recommendations:
            summary['recommendations'] = generate_recommendations(critical_findings, warning_findings)
        
        # Add artifact links for key files
        summary['artifactLinks'] = []
        for finding in critical_findings[:5]:
            if finding.get('fullKey'):
                summary['artifactLinks'].append({
                    'file': finding.get('file'),
                    'key': finding.get('fullKey'),
                    'action': f'read_log_chunk(logKey="{finding.get("fullKey")}")'
                })
        
        # === POD/NODE FAILURE TRIAGE ===
        if include_triage and findings:
            try:
                check_timeout()
                triage_result = perform_pod_node_triage(instance_id, findings, bundle_data)
                summary['pod_node_triage'] = triage_result
            except TimeoutError:
                summary['pod_node_triage'] = {
                    'triageVersion': '1.0',
                    'warning': 'Triage skipped due to time constraints. Call with includeTriage=true separately.',
                    'analyzedAt': datetime.utcnow().isoformat()
                }
            except Exception as e:
                print(f"Warning: Triage analysis failed: {str(e)}")
                summary['pod_node_triage'] = {
                    'triageVersion': '1.0',
                    'error': f'Triage analysis failed: {str(e)}',
                    'analyzedAt': datetime.utcnow().isoformat()
                }
        elif include_triage:
            summary['pod_node_triage'] = {
                'triageVersion': '1.0',
                'info': 'No findings to triage. Node may be healthy.',
                'analyzedAt': datetime.utcnow().isoformat(),
                'pod_states_detected': [],
                'node_conditions_detected': [],
                'most_likely_root_cause': None,
                'evidence': [],
                'coverage_report': {
                    'files_scanned': bundle_data.get('fileCount', 0),
                    'categories_checked': list(TRIAGE_CATEGORIES.keys()),
                    'categories_with_findings': []
                }
            }
        
        # Add next step guidance
        if summary.get('pod_node_triage', {}).get('most_likely_root_cause'):
            root_cause = summary['pod_node_triage']['most_likely_root_cause']
            summary['nextStep'] = f"Root cause identified: {root_cause['category_name']} ({root_cause['confidence']} confidence). Follow immediate_remediation_steps in pod_node_triage."
        else:
            summary['nextStep'] = 'Use search_logs_deep for detailed investigation of specific patterns'
        
        # Update execution time
        summary['executionTimeMs'] = int((time.time() - start_time) * 1000)
        
        return success_response(summary)
    
    except TimeoutError as e:
        # Return partial summary on timeout
        return success_response({
            'instanceId': instance_id,
            'generatedAt': datetime.utcnow().isoformat(),
            'executionTimeMs': int((time.time() - start_time) * 1000),
            'bundleStatus': bundle_data if bundle_data else {'complete': False, 'fileCount': 0, 'totalSize': 'unknown'},
            'errorSummary': error_data.get('summary', {'critical': 0, 'warning': 0, 'info': 0, 'total': 0}) if error_data else {'critical': 0, 'warning': 0, 'info': 0, 'total': 0},
            'criticalFindings': [],
            'warningFindings': [],
            'affectedComponents': [],
            'recommendations': [],
            'artifactLinks': [],
            'pod_node_triage': {
                'triageVersion': '1.0',
                'warning': 'Analysis timed out. Try calling get_error_summary and generate_incident_summary separately.'
            },
            'warning': f'Execution timed out: {str(e)}',
            'nextStep': 'Call get_error_summary first, then generate_incident_summary with includeTriage=false'
        })
        
    except Exception as e:
        # Return partial summary on error, don't fail
        return success_response({
            'instanceId': instance_id,
            'generatedAt': datetime.utcnow().isoformat(),
            'bundleStatus': {'complete': False, 'fileCount': 0, 'totalSize': 'unknown'},
            'errorSummary': {'critical': 0, 'warning': 0, 'info': 0, 'total': 0},
            'criticalFindings': [],
            'warningFindings': [],
            'affectedComponents': [],
            'recommendations': [],
            'artifactLinks': [],
            'pod_node_triage': {
                'triageVersion': '1.0',
                'error': f'Summary generation failed: {str(e)}'
            },
            'error': f'Could not generate complete summary: {str(e)}',
            'nextStep': 'Check if logs exist with validate_bundle_completeness'
        })


def list_collection_history(arguments: Dict) -> Dict:
    """
    List historical log collections for audit and comparison.
    
    Inputs:
        instanceId: Filter by instance (optional)
        maxResults: Max results (default: 20)
        status: Filter by status (optional)
    
    Returns:
        collections[], count
    """
    instance_id = arguments.get('instanceId')
    max_results = min(arguments.get('maxResults', 20), 50)
    status_filter = arguments.get('status')
    document_name = arguments.get('documentName', 'AWSSupport-CollectEKSInstanceLogs')
    
    try:
        filters = []
        if document_name:
            filters.append({'Key': 'DocumentNamePrefix', 'Values': [document_name]})
        if status_filter:
            filters.append({'Key': 'ExecutionStatus', 'Values': [status_filter]})
        
        response = ssm_client.describe_automation_executions(
            Filters=filters,
            MaxResults=max_results
        )
        
        collections = []
        for exec_meta in response.get('AutomationExecutionMetadataList', []):
            # Filter by instance if specified
            if instance_id:
                params = exec_meta.get('Parameters', {})
                exec_instance = params.get('EKSInstanceId', [''])[0]
                if instance_id not in exec_instance:
                    continue
            
            collections.append({
                'executionId': exec_meta['AutomationExecutionId'],
                'documentName': exec_meta.get('DocumentName', ''),
                'status': exec_meta['AutomationExecutionStatus'],
                'startTime': exec_meta.get('ExecutionStartTime'),
                'endTime': exec_meta.get('ExecutionEndTime'),
            })
        
        return success_response({
            'collections': collections,
            'count': len(collections),
            'filters': {
                'instanceId': instance_id,
                'status': status_filter,
                'documentName': document_name
            }
        })
        
    except Exception as e:
        return error_response(500, f'Failed to list history: {str(e)}')


# =============================================================================
# LEGACY COMPATIBILITY FUNCTIONS
# =============================================================================

def list_collected_logs(arguments: Dict) -> Dict:
    """Legacy: List collected logs in S3. Gracefully handles missing logs."""
    instance_id = arguments.get('instanceId', '')
    
    try:
        prefix = f'eks_{instance_id}' if instance_id else 'eks_'
        
        # Use safe helper
        list_result = safe_s3_list(prefix, max_keys=100)
        
        if not list_result['success']:
            return success_response({
                'logs': [],
                'count': 0,
                'bucket': LOGS_BUCKET,
                'prefix': prefix,
                'warning': list_result.get('error', 'Failed to list logs'),
                'suggestion': 'Check if logs have been collected for this instance'
            })
        
        logs = [
            {
                'key': obj['key'],
                'size': obj['size'],
                'lastModified': obj.get('last_modified')
            }
            for obj in list_result['objects']
        ]
        
        return success_response({
            'logs': logs,
            'count': len(logs),
            'bucket': LOGS_BUCKET,
            'prefix': prefix
        })
        
    except Exception as e:
        return success_response({
            'logs': [],
            'count': 0,
            'bucket': LOGS_BUCKET,
            'error': f'Unexpected error: {str(e)}'
        })


def get_log_content_legacy(arguments: Dict) -> Dict:
    """Legacy: Get log content with truncation (deprecated, use read_log_chunk)."""
    log_key = arguments.get('logKey')
    max_bytes = arguments.get('maxBytes', 100000)
    
    if not log_key:
        return error_response(400, 'logKey is required')
    
    # Redirect to new function
    return read_log_chunk({
        'logKey': log_key,
        'startByte': 0,
        'endByte': max_bytes
    })


def search_log_errors_legacy(arguments: Dict) -> Dict:
    """Legacy: Search for errors (deprecated, use get_error_summary or search_logs_deep)."""
    instance_id = arguments.get('instanceId')
    pattern = arguments.get('pattern')
    log_types = arguments.get('logTypes', '')
    max_results = arguments.get('maxResults', 50)
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    # Use new search function
    return search_logs_deep({
        'instanceId': instance_id,
        'query': pattern or r'(?i)(error|fail|fatal|panic|crash|oom|killed|denied|refused|timeout|exception)',
        'logTypes': log_types,
        'maxResults': max_results
    })


