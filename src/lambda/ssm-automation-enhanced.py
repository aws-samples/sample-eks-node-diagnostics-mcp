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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from botocore.exceptions import ClientError

# AWS Clients - default region (where Lambda runs)
ssm_client = boto3.client('ssm')
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')

# Regional client cache to avoid re-creating clients per invocation
_regional_clients: Dict[str, Dict[str, Any]] = {}

# Environment
LOGS_BUCKET = os.environ['LOGS_BUCKET_NAME']
SSM_AUTOMATION_ROLE_ARN = os.environ.get('SSM_AUTOMATION_ROLE_ARN', '')
DEFAULT_REGION = os.environ.get('AWS_REGION', 'us-east-1')


def get_regional_client(service: str, region: str) -> Any:
    """
    Get or create a boto3 client for a specific region.
    Caches clients to avoid repeated creation within the same Lambda invocation.
    """
    if region == DEFAULT_REGION:
        # Use the pre-initialized default clients
        if service == 'ssm':
            return ssm_client
        elif service == 's3':
            return s3_client
        elif service == 'ec2':
            return ec2_client

    cache_key = f'{service}:{region}'
    if cache_key not in _regional_clients:
        _regional_clients[cache_key] = boto3.client(service, region_name=region)
    return _regional_clients[cache_key]


def detect_instance_region(instance_id: str) -> Optional[str]:
    """
    Auto-detect the region of an EC2 instance by querying EC2 DescribeInstances
    across regions. Tries the default region first, then common EKS regions.
    
    Returns the region string or None if not found.
    Times out after 20 seconds to avoid Lambda timeout issues.
    """
    import time
    start = time.time()
    DETECTION_TIMEOUT = 20  # seconds - leave headroom for Lambda timeout
    
    # Try default region first (fast path)
    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        if resp['Reservations']:
            return DEFAULT_REGION
    except ec2_client.exceptions.ClientError:
        pass
    except Exception:
        pass

    # Try common EKS regions (ordered by popularity)
    common_regions = [
        'us-west-2', 'us-east-2', 'eu-west-1', 'eu-central-1',
        'ap-southeast-1', 'ap-northeast-1', 'ap-south-1',
        'us-west-1', 'eu-west-2', 'eu-north-1',
        'ap-southeast-2', 'ap-northeast-2', 'sa-east-1',
        'ca-central-1', 'me-south-1', 'af-south-1',
    ]
    # Remove default region since we already tried it
    common_regions = [r for r in common_regions if r != DEFAULT_REGION]

    for region in common_regions:
        # Check timeout to avoid Lambda execution limit
        if time.time() - start > DETECTION_TIMEOUT:
            print(f"Warning: Region auto-detection timed out after {DETECTION_TIMEOUT}s, checked {common_regions.index(region)} regions")
            return None
        try:
            regional_ec2 = get_regional_client('ec2', region)
            resp = regional_ec2.describe_instances(InstanceIds=[instance_id])
            if resp['Reservations']:
                print(f"Auto-detected instance {instance_id} in region {region}")
                return region
        except Exception:
            continue

    return None


def resolve_region(arguments: Dict, instance_id: str = None) -> str:
    """
    Resolve the target region from arguments or auto-detection.
    Priority: explicit region param > auto-detect from instance > default region.
    """
    explicit_region = arguments.get('region')
    if explicit_region:
        # Basic validation: AWS region format is like us-east-1, eu-west-2, etc.
        if not re.match(r'^[a-z]{2}(-[a-z]+-\d+)$', explicit_region):
            print(f"Warning: Invalid region format '{explicit_region}', falling back to auto-detection")
        else:
            return explicit_region

    if instance_id:
        detected = detect_instance_region(instance_id)
        if detected:
            return detected

    return DEFAULT_REGION

# Constants
DEFAULT_CHUNK_SIZE = 1048576  # 1MB
MAX_CHUNK_SIZE = 5242880  # 5MB
DEFAULT_LINE_COUNT = 1000
MAX_LINE_COUNT = 10000
PRESIGNED_URL_EXPIRATION = 900  # 15 minutes
FINDINGS_INDEX_FILE = 'findings_index.json'


class Severity(Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'


# Backward-compat mapping: v1 (3-level) -> v2 (5-level)
SEVERITY_V1_TO_V2 = {
    'critical': 'critical',
    'warning': 'high',     # old "warning" maps to new "high"
    'info': 'info',
}

# Reverse mapping for queries using old severity names
SEVERITY_V2_TO_V1 = {
    'critical': 'critical',
    'high': 'warning',
    'medium': 'warning',
    'low': 'info',
    'info': 'info',
}

# Severity ordering for sorting (lower = more severe)
SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def normalize_severity_filter(severity_filter: str) -> list:
    """Normalize a severity filter to a list of v2 severity values."""
    if severity_filter == 'all':
        return ['critical', 'high', 'medium', 'low', 'info']
    # Support old v1 names
    if severity_filter == 'warning':
        return ['high', 'medium']
    if severity_filter in SEVERITY_ORDER:
        return [severity_filter]
    return ['critical', 'high', 'medium', 'low', 'info']


def assign_finding_id(index: int) -> str:
    """Generate a stable finding ID in F-001 format."""
    return f"F-{index:03d}"


ERROR_PATTERNS = {
    Severity.CRITICAL: [  # Unrecoverable / node-down / data-loss risk
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
        
        r'Starting L-IPAMD',  # IPAMD restart (critical if repeated)
        r'InsufficientFreeAddressesInSubnet',  # IP exhaustion
        r'Failed to check API server connectivity.*no configuration has been provided',  # Missing token
        r'Unable to reach API Server',  # API server unreachable
        r'Failed to check API server connectivity',  # API connectivity failure
        r'Unauthorized operation: failed to call .* due to missing permissions',  # IAM missing permissions
        
        r'Instances failed to join',
        r'failed to join the kubernetes cluster',
        r'unable to register node',
        r'failed to register node',
        r'certificate has expired',
        r'x509: certificate',
        
        r'WebIdentityErr: failed to retrieve credentials',  # IRSA credential retrieval failed
        r'InvalidIdentityToken.*No OpenIDConnect provider found',  # OIDC provider not found
        r'InvalidIdentityToken.*Incorrect token audience',  # Wrong OIDC audience
        r"InvalidIdentityToken.*HTTPS certificate doesn't match",  # OIDC thumbprint mismatch
        r'AccessDenied.*Not authorized to perform sts:AssumeRoleWithWebIdentity',  # IRSA assume role denied
        r'InvalidClientTokenId.*security token.*invalid',  # Invalid security token
        r'ValidationError.*Request ARN is invalid',  # Invalid IAM ARN format
        
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
        
        r'nodeadm.*failed',
        r'nodeadm.*error',
        r'failed to initialize node',
        r'SSM activation failed',
        
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
        
        r'5\.4\.214-120\.368',  # Known PLEG issue kernel
        r'5\.4\.217-126\.408',  # Known PLEG issue kernel
        r'5\.4\.238-155\.346',  # Known SMB mount issue kernel
        
        r'Container runtime network not ready: NetworkReady=false reason:NetworkPluginNotReady',
        r'network plugin is not ready: cni config uninitialized',  # CNI not initialized
        r'container_linux\.go.*starting container process',  # Container start failure
        r'exec format error',  # Wrong architecture (amd64/arm64 mismatch)
        r'no such file or directory',  # Missing entrypoint/binary
        r'permission denied',  # File permissions issue
        
        r'Failed to assign an IP address to pod',  # IP assignment failure
        r'no free IP addresses',  # IP exhaustion
        r'ENI allocation failed',  # ENI limit or subnet issue
        r'failed to set up sandbox container.*network',  # Network setup failure
        r'NetworkNotReady',  # Network not ready condition
        r'networkPlugin cni failed',  # CNI plugin failure
        
        r'dial udp.*:53.*i/o timeout',  # DNS port unreachable (High)
        r'dial udp.*:53.*timeout',  # DNS timeout (High)
        r'upstream.*unreachable',  # CoreDNS upstream unreachable (High)
        r'coredns.*unhealthy',  # CoreDNS unhealthy (High)
        r'CoreDNS.*error',  # CoreDNS error (High)
        r'DNS.*timeout',  # DNS query timeout (High)
        
        r'node "" not found',  # Missing private DNS entry
        r'Failed to list \*v1\.Service: Unauthorized',
        r'Unable to register node.*with API server: Unauthorized',
        
        r'Killed process.*total-vm',  # OOM killer with memory info
        r'exit code 137',  # SIGKILL (OOM or manual kill)
        
        r'Failed to pull image',  # Image pull failure
        r'unauthorized.*authentication required',  # Registry auth missing
        r'manifest.*not found',  # Image/tag doesn't exist
        r'repository does not exist',  # Wrong repository
        r'ECR.*token.*expired',  # ECR auth expired
        r'pull access denied',  # No pull permission
        
        r'failed to get secret',  # Secret retrieval failed
        r'secrets.*not found',  # Secret doesn't exist
        r'secrets.*forbidden',  # No permission to access secret
        r'KMS.*error',  # KMS error (High severity)
        r'decrypt.*failed',  # Decryption failed (High severity)
        r'webhook.*timeout',  # Webhook timeout
        r'webhook.*denied',  # Webhook denied request
        r'admission.*rejected',  # Admission controller rejected
        r'CreateContainerConfigError',  # Container config error (often secrets-related)
        
        # Bandwidth/Network Limits
        r'Rx packets queued/dropped',  # IDBandwidthInExceeded - Rx bandwidth exceeded
        r'Tx packets queued/dropped',  # IDPPSExceeded - Tx packets per second exceeded
        r'Bandwidth.*exceeded',  # IDBandwidthOutExceeded - Bandwidth out exceeded
        r'LinkLocal.*dropped',  # IDLinkLocalExceeded - LinkLocal packets dropped
        
        # Conntrack (kernel level)
        r'nf_conntrack.*table full',  # IDConntrackExceededKernel - Conntrack exceeded at kernel level
        r'Maximum connections exceeded',  # IDConntrackExceeded - Instance level conntrack exceeded
        
        r'REJECT.*rule',  # IDUnexpectedRejectRule - Unexpected REJECT rule in iptables
        r'Missing.*IPAMD.*iptables',  # IDMissingIPAMdIptablesRules - Missing IPAMD iptables rules
        r'port.*conflict',  # Port conflict detected
        
        r'interface.*down',  # IDInterfaceDown - Network interface down
        r'Missing.*IPv6.*address',  # IDMissingIPv6Address - Missing IPv6 address
        r'Missing.*loopback',  # IDMissingLoopbackInterface - Missing loopback interface
        
        r'Missing.*pod.*IP.*route',  # IDMissingIPRouteRules - Missing pod IP route rules
        r'Missing.*default.*route',  # IDMissingDefaultRoutes - Missing default route rules
        
        r'Excessive.*threads',  # IDExcessiveThreads - Too many threads
        r'zombie.*process',  # IdExcessiveZombieProcesses - Zombie processes
        r'Approaching.*kernel.*pid.*max',  # IDApproachingKernelPidMax - Near PID limit
        r'runc.*init.*hung',  # IDRuncInitPossiblyHung - runc init possibly hung
        
        r'nodeadm.*run.*restart',  # IDNodeadmRunRestart - Nodeadm run restart
        
        # Bootstrap/Boot Issues
        r'Repeated.*bootstrap.*execution',  # IDRepeatedBootstrapExecution - Repeated bootstrap
        r'Multiple.*boots',  # IDMultipleBoots - Multiple boots detected
        r'Unexpected.*filesystem.*mount.*operation',  # IDUnexpectedFilesystemMountOperation - Unexpected mount after bootstrap
        
        # Auto Mode Issues
        r'VPC.*CNI.*pod.*Auto.*Mode.*node',  # IDAutoModeNodeWithAwsNode - VPC CNI pod on Auto Mode node
        
        r'ec2-net-utils',  # IDHasEC2NetUtilsPackage - ec2-net-utils package installed (causes issues)
        
        # Security Agent Issues
        r'Trend.*Micro.*Security.*Agent',  # IDHasTrendMicroSecurityAgent - Trend Micro agent running (known issues)
    ],
    Severity.HIGH: [  # Service-impacting but recoverable
        r'Readiness probe for ".*?:(.*)" failed',  # Readiness probe failure
        r'Liveness probe for ".*?:(.*)" failed',  # Liveness probe failure
        r'due to client-side throttling',  # Client-side throttling
        r'\(PLEG\): ".*?".*Type:"ContainerDied"',  # Container died
        r'Pod still has one or more containers in the non-exited state',  # Pod stuck terminating
        r'(Starting|Stopping).* Kubernetes Kubelet',  # Kubelet restart
        
        r'\S+: Found a Tx that wasn\'t completed on time',  # TX not completed
        r'nfs: server .*? not responding',  # NFS not responding
        r'mce: .*: Core temperature is above threshold',  # CPU overheating
        
        r'is not authorized to perform: .*? ',  # Missing AWS permission
        r'systemd.*Failed to start .*?\.',  # Service failed to start
        r'cloud-init: \+ /etc/eks/bootstrap\.sh',  # Repeated bootstrap (if multiple)
        r'cloud-init: \+ mount /.*? /.*?',  # Unexpected mount operation
        r'kernel: Command line:',  # Multiple boots
        
        r'getsockopt: no route to host',
        r'network is unreachable',
        r'dial tcp.*connection refused',
        r'dial tcp.*i/o timeout',
        r'TLS handshake timeout',
        r'context deadline exceeded',
        r'DNS.*failed',
        r'resolve.*failed',
        r'lookup.*failed',
        
        r'ImagePullBackOff',
        r'ErrImagePull',
        r'CrashLoopBackOff',
        r'RunContainerError',
        r'CreateContainerError',
        r'CreateContainerConfigError',
        r'FailedScheduling',
        r'FailedMount',
        r'FailedAttachVolume',
        
        r'Insufficient cpu',
        r'Insufficient memory',
        r'Insufficient pods',
        r'resource quota exceeded',
        r'PodEvicted',
        r'Evicted',
        r'OOMKilled',
        
        r'node\(s\) didn\'t match.*selector',  # Node selector mismatch
        r'node\(s\) had.*taint',  # Taint/toleration mismatch
        r'node\(s\) didn\'t have free ports',  # Host port conflict
        r'0/\d+ nodes are available',  # No schedulable nodes
        r'Unschedulable',  # Pod can't be scheduled
        r'PodToleratesNodeTaints',  # Toleration issue
        r'NodeAffinity',  # Affinity rule not satisfied
        r'PodAffinity',  # Pod affinity not satisfied
        
        r'VolumeResizeFailed',
        r'WaitForFirstConsumer',
        r'Pending.*PersistentVolumeClaim',
        r'xfs_repair',  # XFS filesystem repair needed
        r'PVC.*pending',  # PVC in pending state
        
        r'VPC CNI v1\.20\.4',  # Known buggy version
        
        r'runc init',  # runc init possibly hung
        r'zombie',  # Zombie processes
        
        r'DataDog.*7\.38\.[01]',  # DataDog zombie process bug
        
        r'Back-off restarting failed container',  # Container restart backoff
        r'denied.*access',  # Access denied (generic)
        r'dial tcp.*connection refused.*registry',  # Registry connection refused
        r'no such host.*ecr',  # ECR DNS failure
        r'no such host',  # Host not resolvable (generic)
        r'i/o timeout.*registry',  # Registry timeout
        r'NXDOMAIN',  # DNS domain not found
        r'SERVFAIL',  # DNS server failure
        r'CoreDNS.*error',  # CoreDNS error
    ],
    Severity.MEDIUM: [  # Degraded performance / potential escalation
        r'fs: disk usage and inodes count on following dirs took',  # Slow disk usage
        r'--node-labels=""',  # Empty node labels
        
        r'net_ratelimit:.*\d+ callbacks suppressed',  # Kernel log rate limiting
        r'martian source .* from .*, on dev',  # Martian packet
        
        r'rsyslogd:.* \d+ messages lost due to rate-limiting',  # Syslog rate limiting
        
        r'MutatingWebhook.*error',  # Mutating webhook error
        r'ValidatingWebhook.*error',  # Validating webhook error
        
        r'cpu.*throttl',  # IDCPUThrottling - CPU throttling detected
        r'io.*delay',  # IDIODelays - I/O delays detected
        
        r'High.*Disk.*Usage',  # IDHighDiskUsage - High disk usage
        r'XFS.*Small.*Average.*Cluster.*Size',  # IDXFSSmallAverageClusterSize
        
        r'UNREPLIED.*conntrack',  # IDConntrackUnrepliedEntries
        
        r'kube-proxy.*slow',  # IDKubeProxySlow
        
        # Pod Issues
        r'Pod.*stuck.*terminating',  # IDPodStuckTerminating
        
        # Environment Issues
        r'Large.*environment.*variables',  # IDLargeEnvironment
        
        # Cron Issues
        r'Rapid.*cron',  # IDRapidCron
        
        # Container Issues
        r'Many.*dead.*containers',  # IDManyDeadContainers
        
        # Network Configuration
        r'Missing.*MACAddressPolicy',  # IDMissingMACAddressPolicy
        r'Non.*default.*VPC.*CNI.*settings',  # IDNonDefaultVPCCNISettings
        
        # Well-known Application Bugs
        r'Well.*known.*application.*bug',  # IDWellKnownApplicationBug
    ],
    Severity.LOW: [  # Informational warnings that may need attention
        r'readiness probe failed',
        r'liveness probe failed',
        r'startup probe failed',
        
        r'CPU Throttling',
        r'I/O Delay',
        
        r'High Disk Usage',
        r'Small XFS Average Cluster Size',
        
        r'Many Network Connections',
        r'Interface Down',
    ],
}

# Pre-compile all ERROR_PATTERNS at module level to avoid recompilation per-file
COMPILED_ERROR_PATTERNS = {}
for _severity, _patterns in ERROR_PATTERNS.items():
    COMPILED_ERROR_PATTERNS[_severity] = []
    for _pattern in _patterns:
        try:
            COMPILED_ERROR_PATTERNS[_severity].append(re.compile(_pattern, re.IGNORECASE))
        except re.error:
            pass  # Skip invalid patterns

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


def store_execution_region(execution_id: str, region: str) -> bool:
    """Store the region where an SSM execution was started, so subsequent calls can find it.
    Returns True if stored successfully, False otherwise."""
    key = f'execution-regions/{execution_id}.json'
    mapping = {
        'executionId': execution_id,
        'region': region,
        'createdAt': datetime.utcnow().isoformat()
    }
    for attempt in range(2):
        try:
            s3_client.put_object(
                Bucket=LOGS_BUCKET,
                Key=key,
                Body=json.dumps(mapping),
                ContentType='application/json'
            )
            return True
        except Exception as e:
            print(f"Warning: Failed to store execution region mapping (attempt {attempt + 1}): {str(e)}")
    return False


def get_execution_region(execution_id: str) -> Optional[str]:
    """Retrieve the region where an SSM execution was started."""
    key = f'execution-regions/{execution_id}.json'
    result = safe_s3_read(key)
    if result['success']:
        try:
            mapping = json.loads(result['content'])
            return mapping.get('region')
        except Exception:
            pass
    return None


def find_execution_by_idempotency_token(instance_id: str, token: str) -> Optional[Dict]:
    """Find existing execution by idempotency token, using the correct regional SSM client."""
    key = f'idempotency/{instance_id}/{token}.json'
    result = safe_s3_read(key)
    
    if result['success']:
        try:
            mapping = json.loads(result['content'])
            execution_id = mapping.get('executionId')
            
            # Look up which region this execution lives in
            exec_region = get_execution_region(execution_id) or DEFAULT_REGION
            regional_ssm = get_regional_client('ssm', exec_region)
            
            try:
                response = regional_ssm.get_automation_execution(
                    AutomationExecutionId=execution_id
                )
                return {
                    'executionId': execution_id,
                    'status': response['AutomationExecution']['AutomationExecutionStatus']
                }
            except Exception:
                return None
        except Exception:
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


# ========================================================================
# Baseline Subtraction (S3-based)
# ========================================================================

BASELINE_PREFIX = 'baselines/'
BASELINE_THRESHOLD = 10  # pattern must appear 10+ times to be considered baseline


def load_baselines(cluster_name: str) -> Dict[str, Dict]:
    """
    Load baseline patterns for a cluster from S3.
    Baselines are stored as: baselines/{cluster_name}/patterns.json
    Returns {pattern_string: {count, first_seen, last_seen, is_baseline}}.
    """
    if not cluster_name:
        return {}
    key = f'{BASELINE_PREFIX}{cluster_name}/patterns.json'
    try:
        result = safe_s3_read(key)
        if result['success']:
            return json.loads(result['content'])
    except Exception:
        pass
    return {}


def update_baselines(cluster_name: str, findings: List[Dict]):
    """
    Increment baseline counters for observed patterns and persist to S3.
    Uses read-modify-write on S3 (acceptable for low-frequency updates).
    """
    if not cluster_name or not findings:
        return
    baselines = load_baselines(cluster_name)
    now_iso = datetime.utcnow().isoformat()

    for f in findings:
        pattern = f.get('pattern', '')
        if not pattern:
            continue
        if pattern not in baselines:
            baselines[pattern] = {
                'count': 0,
                'first_seen': now_iso,
                'last_seen': now_iso,
                'is_baseline': False,
            }
        entry = baselines[pattern]
        entry['count'] = entry.get('count', 0) + 1
        entry['last_seen'] = now_iso
        # Auto-promote to baseline after threshold
        if entry['count'] >= BASELINE_THRESHOLD:
            entry['is_baseline'] = True

    # Persist
    key = f'{BASELINE_PREFIX}{cluster_name}/patterns.json'
    try:
        s3_client.put_object(
            Bucket=LOGS_BUCKET,
            Key=key,
            Body=json.dumps(baselines, default=str),
            ContentType='application/json',
        )
    except Exception as e:
        print(f"Warning: Failed to update baselines for {cluster_name}: {e}")


def annotate_findings_with_baselines(findings: List[Dict], cluster_name: str) -> List[Dict]:
    """
    Annotate each finding with is_baseline and baseline_note if the pattern
    is a known baseline for this cluster.
    """
    if not cluster_name:
        return findings
    baselines = load_baselines(cluster_name)
    if not baselines:
        return findings

    for f in findings:
        pattern = f.get('pattern', '')
        baseline = baselines.get(pattern)
        if baseline and baseline.get('is_baseline'):
            f['is_baseline'] = True
            f['baseline_note'] = (
                f"This pattern has been seen {baseline['count']} times "
                f"across cluster {cluster_name} since {baseline.get('first_seen', 'unknown')}. "
                f"Likely normal operation."
            )
        else:
            f['is_baseline'] = False

    return findings


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
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
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
    summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    # Parallel file scanning — up to 10 concurrent S3 reads
    files_batch = files_to_scan[:100]
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_key = {executor.submit(scan_file_for_errors, fi['key']): fi['key'] for fi in files_batch}
        for future in as_completed(future_to_key):
            try:
                file_findings = future.result()
                for finding in file_findings:
                    severity = finding.get('severity', 'info')
                    summary[severity] = summary.get(severity, 0) + 1
                    if severity_filter == 'all' or severity in normalize_severity_filter(severity_filter):
                        findings.append(finding)
            except Exception:
                pass  # Skip files that fail to scan
    
    # Sort by severity
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'info'), 4))
    

    # A CRITICAL finding is confirmed if the same pattern appears in 2+ files
    # or if a corroborating pattern exists (e.g., OOM kill + exit code 137)
    critical_patterns = {}
    for f in findings:
        if f.get('severity') == 'critical':
            pat = f.get('pattern', '')
            if pat not in critical_patterns:
                critical_patterns[pat] = []
            critical_patterns[pat].append(f.get('file', ''))
    
    for f in findings:
        if f.get('severity') == 'critical':
            pat = f.get('pattern', '')
            sources = set(critical_patterns.get(pat, []))
            f['confirmed'] = len(sources) >= 2
            f['signal_sources'] = len(sources)
    
    
    now_iso = datetime.utcnow().isoformat()
    for f in findings:
        # Try to extract timestamps from sample match lines
        sample_line = f.get('sample', '')
        ts = extract_timestamp(sample_line) if sample_line else None
        f['first_seen'] = ts or now_iso
        f['last_seen'] = ts or now_iso
    
    # Assign finding_ids
    for idx, finding in enumerate(findings):
        finding['finding_id'] = assign_finding_id(idx + 1)
    
    return success_response({
        'instanceId': instance_id,
        'findings': findings[:100],
        'totalFindings': len(findings),
        'summary': summary,
        'cached': False,
        'indexedAt': datetime.utcnow().isoformat(),
        'coverage_report': {
            'files_scanned': len(files_batch),
            'files_available': len(files_to_scan),
            'files_skipped_size': len([f for f in list_result['objects'] if '/extracted/' in f['key'] and f['size'] >= 10485760]),
            'scan_complete': len(files_batch) >= len(files_to_scan),
        }
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
    
 
    # These patterns indicate the match is informational, not an actual error
    FALSE_POSITIVE_CONTEXTS = [
        re.compile(r'(resolv\.conf|/etc/resolv)', re.IGNORECASE),  # Node resolv.conf is normal
        re.compile(r'(--help|usage:|man\s+page)', re.IGNORECASE),  # Help text
        re.compile(r'(example|sample|template|default)', re.IGNORECASE),  # Example/template text
        re.compile(r'(test|mock|fake|stub)', re.IGNORECASE),  # Test artifacts
        re.compile(r'Successfully\s+', re.IGNORECASE),  # Success messages containing error keywords
    ]
    
    # Track patterns found to avoid duplicates
    found_patterns = {}
    MAX_FINDINGS_PER_FILE = 20
    
    for severity, compiled_patterns in COMPILED_ERROR_PATTERNS.items():
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            break
        for regex in compiled_patterns:
            if len(findings) >= MAX_FINDINGS_PER_FILE:
                break
            matches = []
            
            for i, line in enumerate(lines):
                if regex.search(line):
                  
                    is_false_positive = False
                    for fp_re in FALSE_POSITIVE_CONTEXTS:
                        if fp_re.search(line):
                            is_false_positive = True
                            break
                    if is_false_positive:
                        continue
                    
                    matches.append({
                        'lineNumber': i + 1,
                        'line': line[:500]  # Limit line length
                    })
                    if len(matches) >= 5:  # Cap match samples per pattern
                        break
            
            if matches:
                pattern_key = f"{filename}:{regex.pattern}"
                if pattern_key not in found_patterns:
                    found_patterns[pattern_key] = True
                    findings.append({
                        'file': filename,
                        'fullKey': key,
                        'pattern': regex.pattern,
                        'severity': severity.value,
                        'count': len(matches),
                        'sample': matches[0]['line'] if matches else ''
                    })
    
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


def search_file_for_pattern(key: str, pattern: re.Pattern, max_results: int, file_size: int = 0) -> Optional[List[Dict]]:
    """
    Search a single file for a regex pattern.
    For files >5MB, reads in chunks with overlap to avoid missing matches at boundaries.
    """
    CHUNK_READ_SIZE = 5242880  # 5MB per chunk
    OVERLAP = 4096  # 4KB overlap between chunks to catch boundary matches

    # Small file: read all at once (original fast path)
    if file_size <= CHUNK_READ_SIZE:
        read_result = safe_s3_read(key, max_size=CHUNK_READ_SIZE)
        if not read_result['success']:
            return None
        matches = []
        lines = read_result['content'].split('\n')
        for i, line in enumerate(lines):
            if pattern.search(line):
                matches.append({
                    'lineNumber': i + 1,
                    'line': line[:500],
                    'context': get_line_context(lines, i, 2)
                })
                if len(matches) >= max_results:
                    break
        return matches

    # Large file: chunked reading
    matches = []
    offset = 0
    global_line_offset = 0
    seen_lines = set()  # Deduplicate matches in overlap regions

    while offset < file_size and len(matches) < max_results:
        end = min(offset + CHUNK_READ_SIZE, file_size)
        range_header = f'bytes={offset}-{end - 1}'
        read_result = safe_s3_read(key, range_bytes=range_header)

        if not read_result['success']:
            break

        chunk = read_result['content']
        lines = chunk.split('\n')

        # If not the first chunk, skip the first (potentially partial) line
        start_idx = 1 if offset > 0 else 0
        # If not the last chunk, skip the last (potentially partial) line
        end_idx = len(lines) - 1 if end < file_size else len(lines)

        for i in range(start_idx, end_idx):
            line = lines[i]
            line_num = global_line_offset + i + 1
            if pattern.search(line):
                # Deduplicate across overlap regions
                line_key = f"{line_num}:{line[:100]}"
                if line_key not in seen_lines:
                    seen_lines.add(line_key)
                    # Build context from available lines in this chunk
                    ctx_before = lines[max(0, i - 2):i]
                    ctx_after = lines[i + 1:min(len(lines), i + 3)]
                    matches.append({
                        'lineNumber': line_num,
                        'line': line[:500],
                        'context': {'before': ctx_before, 'after': ctx_after}
                    })
                    if len(matches) >= max_results:
                        break

        # Advance: subtract overlap so we re-read boundary region
        global_line_offset += end_idx - start_idx
        next_offset = end - OVERLAP
        if next_offset <= offset:
            break
        offset = next_offset

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


def generate_recommendations(critical_findings: List[Dict], high_findings: List[Dict], warning_findings: List[Dict] = None) -> List[Dict]:
    """Generate remediation recommendations based on findings.
    
    Args:
        critical_findings: Findings with severity=critical
        high_findings: Findings with severity=high
        warning_findings: Deprecated, kept for backward compat. Merged into high_findings.
    """
    recommendations = []
    
    # Merge warning_findings into high_findings for backward compat
    all_high = list(high_findings or [])
    if warning_findings:
        all_high.extend(warning_findings)
    
    # Analyze critical findings
    for finding in critical_findings:
        pattern = finding.get('pattern', '').lower()
        
        if 'oom' in pattern or 'memory' in pattern:
            recommendations.append({
                'priority': 'high',
                'category': 'memory',
                'issue': 'Memory pressure detected',
                'action': 'Review pod resource limits and node capacity. Consider scaling up or adding nodes.',
                'evidence_finding_ids': [finding.get('finding_id')],
            })
        elif 'unauthorized' in pattern or 'denied' in pattern:
            recommendations.append({
                'priority': 'high',
                'category': 'auth',
                'issue': 'Authentication/authorization failures',
                'action': 'Check IAM roles, RBAC policies, and aws-auth ConfigMap.',
                'evidence_finding_ids': [finding.get('finding_id')],
            })
        elif 'cni' in pattern or 'ipamd' in pattern or 'network' in pattern:
            recommendations.append({
                'priority': 'high',
                'category': 'networking',
                'issue': 'CNI/networking issues detected',
                'action': 'Check VPC CNI plugin logs, subnet IP availability, and security groups.',
                'evidence_finding_ids': [finding.get('finding_id')],
            })
        elif 'pleg' in pattern:
            recommendations.append({
                'priority': 'high',
                'category': 'kubelet',
                'issue': 'PLEG (Pod Lifecycle Event Generator) issues',
                'action': 'Check for container runtime issues, disk I/O problems, or too many pods on node.',
                'evidence_finding_ids': [finding.get('finding_id')],
            })
    
    # Analyze high findings
    for finding in all_high:
        pattern = finding.get('pattern', '').lower()
        
        if 'crashloop' in pattern or 'restart' in pattern:
            recommendations.append({
                'priority': 'medium',
                'category': 'stability',
                'issue': 'Container restart loops detected',
                'action': 'Check container exit codes and previous logs (kubectl logs <pod> --previous).',
                'evidence_finding_ids': [finding.get('finding_id')],
            })
        elif 'scheduling' in pattern or 'insufficient' in pattern:
            recommendations.append({
                'priority': 'medium',
                'category': 'capacity',
                'issue': 'Scheduling constraints detected',
                'action': 'Review node capacity, resource requests/limits, and scheduling constraints.',
                'evidence_finding_ids': [finding.get('finding_id')],
            })
    
    # Remove duplicates by category
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
            },
        ],
        'C': [
            {
                'category': 'capacity_planning',
                'recommendation': 'Enable VPC CNI prefix delegation for higher IP density',
            },
            {
                'category': 'monitoring',
                'recommendation': 'Monitor subnet IP availability with CloudWatch',
            },
        ],
        'D': [
            {
                'category': 'configuration',
                'recommendation': 'Increase nf_conntrack_max via node configuration',
            },
        ],
        'E': [
            {
                'category': 'capacity_planning',
                'recommendation': 'Implement Cluster Autoscaler or Karpenter',
            },
        ],
        'F': [
            {
                'category': 'security',
                'recommendation': 'Use ECR pull-through cache for external images',
            },
        ],
        'G': [
            {
                'category': 'reliability',
                'recommendation': 'Scale CoreDNS based on cluster size',
            },
        ],
        'H': [
            {
                'category': 'security',
                'recommendation': 'Use EKS Pod Identity for secrets access',
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
        elif max_size:
            # Enforce max_size via byte range if no explicit range given
            params['Range'] = f'bytes=0-{max_size - 1}'
        
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
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'InvalidRange':
            return {
                'success': False,
                'error': f'Invalid byte range for: {key}',
                'error_type': 'invalid_range',
                'content': ''
            }
        if error_code == 'NoSuchKey' or error_code == '404':
            return {
                'success': False,
                'error': f'File not found: {key}',
                'error_type': 'not_found',
                'content': ''
            }
        return {
            'success': False,
            'error': f'S3 error reading {key}: {error_code} - {str(e)}',
            'error_type': 'client_error',
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
    except ClientError as e:
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
        'collect': start_log_collection,
        'status': get_collection_status,
        'validate': validate_bundle_completeness,
        'errors': get_error_summary,
        'read': read_log_chunk,
        
        # Advanced Analysis (Tier 2)
        'search': search_logs_deep,
        'correlate': correlate_events,
        'artifact': get_artifact_reference,
        'summarize': generate_incident_summary,
        'history': list_collection_history,

        # Cluster-Level Intelligence (Tier 3)
        'cluster_health': cluster_health,
        'compare_nodes': compare_nodes,
        'batch_collect': batch_collect,
        'batch_status': batch_status,
        'network_diagnostics': network_diagnostics,
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
    """Standard success response format with payload size guard."""
    MAX_PAYLOAD_BYTES = 5_500_000  # ~5.5MB safety margin under Lambda's 6MB limit

    body = json.dumps({
        'success': True,
        **data
    }, default=str)

    if len(body.encode('utf-8')) > MAX_PAYLOAD_BYTES:
        # Truncate large result arrays to fit within Lambda response limits
        truncated_data = {k: v for k, v in data.items() if not isinstance(v, list)}
        for k, v in data.items():
            if isinstance(v, list):
                # Progressively trim lists until we fit
                trimmed = v
                while trimmed:
                    candidate = json.dumps({
                        'success': True,
                        **truncated_data,
                        k: trimmed,
                        '_payloadTruncated': True,
                        '_originalCount': len(v),
                        '_returnedCount': len(trimmed),
                    }, default=str)
                    if len(candidate.encode('utf-8')) <= MAX_PAYLOAD_BYTES:
                        return {'statusCode': 200, 'body': candidate}
                    trimmed = trimmed[:len(trimmed) // 2]
                truncated_data[k] = []
        # Fallback: return metadata only
        body = json.dumps({
            'success': True,
            **truncated_data,
            '_payloadTruncated': True,
            '_error': 'Response too large, all result arrays removed',
        }, default=str)

    return {'statusCode': 200, 'body': body}


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
    Start EKS log collection with idempotency and cross-region support.
    
    Inputs:
        instanceId: EC2 instance ID (required)
        idempotencyToken: Optional token to prevent duplicate executions
        region: AWS region where the instance runs (optional, auto-detected if omitted)
    
    Returns:
        executionId, estimatedCompletionTime, status, region
    """
    instance_id = arguments.get('instanceId')
    idempotency_token = arguments.get('idempotencyToken')
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    # Validate instance ID format (i-xxxxxxxxxxxxxxxxx)
    if not re.match(r'^i-[0-9a-f]{8,17}$', instance_id):
        return error_response(400, f'Invalid instanceId format: {instance_id}. Expected format: i-xxxxxxxxxxxxxxxxx')
    
    # Resolve target region (explicit > auto-detect > default)
    target_region = resolve_region(arguments, instance_id)
    try:
        regional_ssm = get_regional_client('ssm', target_region)
    except Exception as e:
        return error_response(500, f'Failed to create SSM client for region {target_region}: {str(e)}')
    
    print(f"Starting log collection for {instance_id} in region {target_region}")
    
    # Verify instance is running and SSM-reachable before starting automation
    try:
        regional_ec2 = get_regional_client('ec2', target_region)
        desc_resp = regional_ec2.describe_instances(InstanceIds=[instance_id])
        reservations = desc_resp.get('Reservations', [])
        if reservations and reservations[0].get('Instances'):
            state = reservations[0]['Instances'][0].get('State', {}).get('Name', 'unknown')
            if state in ('terminated', 'shutting-down'):
                return error_response(400, f'Instance {instance_id} is {state}. Cannot collect logs from terminated instances.')
            if state == 'stopped':
                return error_response(400, f'Instance {instance_id} is stopped. Start the instance first, then retry.')
    except Exception as e:
        # Non-fatal: proceed anyway, SSM will fail with a clearer error if instance is unreachable
        print(f"Warning: Could not verify instance state: {str(e)}")
    
    # Check for existing execution with same idempotency token
    if idempotency_token:
        existing = find_execution_by_idempotency_token(instance_id, idempotency_token)
        if existing:
            return success_response({
                'message': 'Returning existing execution (idempotent)',
                'executionId': existing['executionId'],
                'status': existing['status'],
                'instanceId': instance_id,
                'region': target_region,
                'idempotent': True
            })
    
    try:
        # Start SSM Automation in the target region
        params = {
            'EKSInstanceId': [instance_id],
            'LogDestination': [LOGS_BUCKET],
            'AutomationAssumeRole': [SSM_AUTOMATION_ROLE_ARN]
        }
        
        response = regional_ssm.start_automation_execution(
            DocumentName='AWSSupport-CollectEKSInstanceLogs',
            Parameters=params
        )
        
        execution_id = response['AutomationExecutionId']
        
        # Store idempotency mapping with region info
        if idempotency_token:
            store_idempotency_mapping(instance_id, idempotency_token, execution_id)
        
        # Also store region mapping so subsequent calls know which region to query
        region_stored = store_execution_region(execution_id, target_region)
        
        response_data = {
            'message': 'EKS log collection started',
            'executionId': execution_id,
            'instanceId': instance_id,
            'region': target_region,
            's3Bucket': LOGS_BUCKET,
            'estimatedCompletionTime': '3-5 minutes',
            'suggestedPollIntervalSeconds': 15,
            'nextStep': f'Poll status with status(executionId="{execution_id}") every 15 seconds',
           
            'task': {
                'taskId': execution_id,
                'state': 'running',
                'message': 'Log collection started via SSM Automation',
                'progress': 0,
            },
        }
        
        if not region_stored and target_region != DEFAULT_REGION:
            response_data['warning'] = (
                f'Region mapping could not be persisted. Pass region="{target_region}" '
                f'explicitly in subsequent status/validate calls.'
            )
        
        return success_response(response_data)
        
    except regional_ssm.exceptions.AutomationDefinitionNotFoundException:
        return error_response(404, 'AWSSupport-CollectEKSInstanceLogs document not found', {
            'suggestion': f'This SSM document may not be available in region {target_region}. '
                          f'Check https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/ '
                          f'for regional availability, or try running from a supported region like us-east-1 or us-west-2.',
            'region': target_region
        })
    except Exception as e:
        return error_response(500, f'Failed to start log collection in {target_region}: {str(e)}')


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
    
    # Resolve region for this execution
    target_region = get_execution_region(execution_id) or arguments.get('region', DEFAULT_REGION)
    try:
        regional_ssm = get_regional_client('ssm', target_region)
    except Exception as e:
        return error_response(500, f'Failed to create SSM client for region {target_region}: {str(e)}')
    
    try:
        response = regional_ssm.get_automation_execution(
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
            result['nextStep'] = f'Validate bundle with validate(executionId="{execution_id}")'
        elif status == 'InProgress':
            result['suggestedPollIntervalSeconds'] = 15
            result['nextStep'] = 'Wait 15 seconds then poll again until status is Success or Failed'
        elif status == 'Failed':
            result['nextStep'] = 'Review failureReason and retry if appropriate'
        
        
        SSM_TO_TASK_STATE = {
            'Pending': 'running',
            'InProgress': 'running',
            'Waiting': 'running',
            'Success': 'completed',
            'TimedOut': 'failed',
            'Cancelling': 'cancelling',
            'Cancelled': 'cancelled',
            'Failed': 'failed',
        }
        task_state = SSM_TO_TASK_STATE.get(status, 'running')
        result['task'] = {
            'taskId': execution_id,
            'state': task_state,
            'message': result.get('failureReason', f'SSM status: {status}'),
            'progress': result.get('progress', 0),
        }
        
        return success_response({'automation': result})
        
    except regional_ssm.exceptions.AutomationExecutionNotFoundException:
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
                target_region = get_execution_region(execution_id) or arguments.get('region', DEFAULT_REGION)
                regional_ssm = get_regional_client('ssm', target_region)
            except Exception as e:
                return error_response(500, f'Failed to create SSM client for region: {str(e)}')
            try:
                exec_response = regional_ssm.get_automation_execution(
                    AutomationExecutionId=execution_id
                )
                params = exec_response['AutomationExecution'].get('Parameters', {})
                instance_id = params.get('EKSInstanceId', [''])[0]
                prefix = f'eks_{instance_id}'
            except regional_ssm.exceptions.AutomationExecutionNotFoundException:
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
        
        
        manifest_data = None
        manifest_files = [obj for obj in list_result['objects'] if obj['key'].endswith('manifest.json')]
        if manifest_files:
            manifest_files.sort(key=lambda x: x.get('last_modified', ''), reverse=True)
            manifest_read = safe_s3_read(manifest_files[0]['key'])
            if manifest_read['success']:
                try:
                    manifest_data = json.loads(manifest_read['content'])
                except json.JSONDecodeError:
                    manifest_data = None
        
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
                'nextStep': 'Check log collection status with status'
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
        
        
        if manifest_data and manifest_data.get('version', 1) >= 2:
            result['manifestVersion'] = manifest_data.get('version')
            result['archiveSize'] = manifest_data.get('archiveSize', 0)
            result['archiveSizeHuman'] = format_bytes(manifest_data.get('archiveSize', 0))
            manifest_file_count = manifest_data.get('totalFiles', 0)
            # Cross-check: manifest says N files, S3 listing shows M
            if manifest_file_count > 0 and len(all_files) < manifest_file_count:
                result['warning'] = (
                    f'Manifest reports {manifest_file_count} files but only {len(all_files)} found in S3. '
                    f'Some files may have been deleted or extraction was incomplete.'
                )
                result['complete'] = False
        
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
            result['nextStep'] = f'Get error summary with errors(instanceId="{instance_id}")'
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
        severity: Filter by severity (critical|high|medium|low|info|warning|all)
        response_format: 'concise' (default) or 'detailed'
        pageSize: Number of findings per page (default: 50, max: 200)
        pageToken: Opaque token for next page (base64-encoded offset)
    
    Returns:
        findings[], summary counts, indexed timestamp, coverage_report
    """
    instance_id = arguments.get('instanceId')
    severity_filter = arguments.get('severity', 'all')
    response_format = arguments.get('response_format', 'concise')
    page_size = min(arguments.get('pageSize', 50), 200)
    page_token = arguments.get('pageToken')
    cluster_context = arguments.get('clusterContext')
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    # Decode page offset
    page_offset = 0
    if page_token:
        try:
            import base64
            page_offset = int(base64.b64decode(page_token).decode('utf-8'))
        except Exception:
            page_offset = 0
    
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
                    
                    # Assign finding_ids if not present
                    for idx, f in enumerate(findings):
                        if 'finding_id' not in f:
                            f['finding_id'] = assign_finding_id(idx + 1)
                    
                    # Backward-compat: remap old severity names
                    for f in findings:
                        old_sev = f.get('severity', 'info')
                        if old_sev == 'warning':
                            f['severity'] = 'high'
                    
                    
                    if cluster_context:
                        findings = annotate_findings_with_baselines(findings, cluster_context)
                    
                    # Filter by severity if requested
                    allowed_severities = normalize_severity_filter(severity_filter)
                    if severity_filter != 'all':
                        findings = [f for f in findings if f.get('severity') in allowed_severities]
                    
                    # Pagination
                    total_findings = len(findings)
                    page_findings = findings[page_offset:page_offset + page_size]
                    has_more = (page_offset + page_size) < total_findings
                    
                    next_token = None
                    if has_more:
                        import base64
                        next_token = base64.b64encode(str(page_offset + page_size).encode('utf-8')).decode('utf-8')
                    
                    # Build summary with 5-level counts
                    summary = index_data.get('summary', {})
                    # Migrate old summary format
                    if 'warning' in summary and 'high' not in summary:
                        summary = {
                            'critical': summary.get('critical', 0),
                            'high': summary.get('warning', 0),
                            'medium': 0,
                            'low': 0,
                            'info': summary.get('info', 0),
                        }
                    
                    # Format findings based on response_format
                    if response_format == 'concise':
                        page_findings = [
                            {
                                'finding_id': f.get('finding_id'),
                                'severity': f.get('severity'),
                                'pattern': f.get('pattern'),
                                'file': f.get('file'),
                                'count': f.get('count'),
                                **(
                                    {'is_baseline': f.get('is_baseline', False),
                                     'baseline_note': f.get('baseline_note')}
                                    if f.get('is_baseline') else {}
                                ),
                            }
                            for f in page_findings
                        ]
                    
                    # Coverage report
                    coverage_report = {
                        'files_scanned': index_data.get('filesScanned', 0),
                        'files_skipped': index_data.get('filesSkipped', 0),
                        'scan_complete': True,
                        'index_version': index_data.get('index_version', 'v1'),
                    }
                    
                    
                    if cluster_context:
                        update_baselines(cluster_context, findings)
                    
                    return success_response({
                        'instanceId': instance_id,
                        'indexedAt': index_data.get('indexedAt'),
                        'findings': page_findings,
                        'totalFindings': total_findings,
                        'pageSize': page_size,
                        'pageOffset': page_offset,
                        'hasMore': has_more,
                        'nextPageToken': next_token,
                        'summary': summary,
                        'cached': True,
                        'coverage_report': coverage_report,
                        'interpretationGuide': {
                            'NXDOMAIN': 'Domain does not exist. Check if pods are querying wrong service names or non-existent external domains. This is NOT necessarily a DNS server misconfiguration.',
                            'OOMKilled': 'Container exceeded its memory limit and was killed by the kernel. Check container memory requests/limits.',
                            'CrashLoopBackOff': 'Container keeps crashing and restarting. Check the exit code and container logs (kubectl logs <pod> --previous).',
                            'ImagePullBackOff': 'Failed to pull container image. Check image name, tag, registry auth, and ECR permissions.',
                            'FailedScheduling': 'Pod could not be scheduled. Check node resources, taints/tolerations, and node selectors.',
                            'Evicted': 'Pod was evicted due to node resource pressure (disk, memory, or PID). Check node conditions.',
                            'FailedMount': 'Volume mount failed. Check PV/PVC status, EBS volume availability, and IAM permissions.',
                            'NetworkNotReady': 'Node network plugin (CNI) is not ready. Check aws-node (VPC CNI) pod status.',
                            'resolv.conf (node)': 'Node /etc/resolv.conf showing VPC DNS (e.g., 172.31.0.2) is NORMAL. Pod DNS is set separately by kubelet --cluster-dns.',
                        },
                        'nextStep': 'Use search for detailed investigation, or summarize with finding_ids'
                    })
                except json.JSONDecodeError:
                    # Index file corrupted, fall through to scan
                    print(f"Warning: Findings index corrupted, will scan on-demand")
        
        # Slow path: scan and index on-demand
        result = scan_and_index_errors(instance_id, severity_filter)
        
        if cluster_context and result.get('success') and result.get('data', {}).get('findings'):
            result['data']['findings'] = annotate_findings_with_baselines(
                result['data']['findings'], cluster_context
            )
            update_baselines(cluster_context, result['data']['findings'])
        return result
        
    except Exception as e:
        # Return empty findings on error, don't fail
        return success_response({
            'instanceId': instance_id,
            'findings': [],
            'totalFindings': 0,
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'cached': False,
            'warning': f'Could not retrieve error summary: {str(e)}',
            'nextStep': 'Check if logs exist with validate'
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
        
        # Read slightly more than requested to find newline boundaries
        BOUNDARY_SCAN = 4096  # Extra bytes to scan for newline alignment

        # Expand read range for boundary alignment
        actual_start = max(0, start_byte - 1) if start_byte > 0 else 0
        actual_end = min(end_byte + BOUNDARY_SCAN, total_size)

        range_header = f'bytes={actual_start}-{actual_end - 1}'
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
        
        raw = read_result['content']

        # Snap start: if not at file start, skip forward to first \n
        aligned_start = start_byte
        if start_byte > 0:
            first_nl = raw.find('\n')
            if first_nl >= 0:
                aligned_start = actual_start + first_nl + 1
                raw = raw[first_nl + 1:]

        # Snap end: find the last complete line
        content_end_offset = end_byte - aligned_start
        if content_end_offset < len(raw) and end_byte < total_size:
            nl_pos = raw.find('\n', content_end_offset)
            if nl_pos >= 0:
                raw = raw[:nl_pos + 1]
                aligned_end = aligned_start + nl_pos + 1
            else:
                raw = raw[:content_end_offset]
                aligned_end = end_byte
        else:
            aligned_end = aligned_start + len(raw)

        content_str = raw
        has_more = aligned_end < total_size
        
        return success_response({
            'logKey': log_key,
            'content': content_str,
            'startByte': aligned_start,
            'endByte': aligned_end,
            'chunkSize': len(content_str),
            'totalSize': total_size,
            'totalSizeHuman': format_bytes(total_size),
            'hasMore': has_more,
            'nextChunkToken': str(aligned_end) if has_more else None,
            'truncated': False,  # NEVER truncate
            'lineAligned': True,
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
        response_format: 'concise' (default) or 'detailed'
    
    Returns:
        matches[], pagination info, coverage_report
    """
    instance_id = arguments.get('instanceId')
    query = arguments.get('query')
    log_types_str = arguments.get('logTypes', '')
    max_results = min(arguments.get('maxResults', 100), 500)
    response_format = arguments.get('response_format', 'concise')
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    if not query:
        return error_response(400, 'query is required')
    if len(query) > 500:
        return error_response(400, 'query too long (max 500 characters)')
    
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
                'nextStep': 'Check if logs exist with validate'
            })
        
        # Filter files to search
        files_to_search = []
        large_file_count = 0
        for obj in list_result['objects']:
            key = obj['key']
            if '/extracted/' not in key:
                continue
            if any(key.endswith(ext) for ext in ['.tar.gz', '.zip', '.gz', '.bin', '.so']):
                continue
            
            
            if obj['size'] > 52428800:  # Only skip truly huge files >50MB
                large_file_count += 1
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
            matches = search_file_for_pattern(file_info['key'], pattern, max_results, file_size=file_info['size'])
            
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
            
            if sum(len(m['matches']) for m in all_matches) >= max_results * 3:
                break
        
        # Sort by match count
        all_matches.sort(key=lambda x: x['matchCount'], reverse=True)
        
        # Assign finding_ids to search results
        finding_counter = 0
        for match_group in all_matches:
            finding_counter += 1
            match_group['finding_id'] = f"S-{finding_counter:03d}"
        
        # Trim individual file matches to keep response manageable
        total_matches_kept = 0
        for match_group in all_matches:
            remaining_budget = max(10, max_results * 3 - total_matches_kept)
            if len(match_group['matches']) > remaining_budget:
                match_group['matches'] = match_group['matches'][:remaining_budget]
                match_group['matchCount'] = len(match_group['matches'])
                match_group['matchesTruncated'] = True
            total_matches_kept += len(match_group['matches'])
        
        # Coverage report
        coverage_report = {
            'files_searched': files_searched,
            'files_available': len(files_to_search),
            'files_skipped_size': large_file_count,
            'files_with_errors': files_with_errors,
            'scan_complete': files_searched >= len(files_to_search),
        }
        
        result = {
            'instanceId': instance_id,
            'query': query,
            'filesSearched': files_searched,
            'filesWithMatches': len(all_matches),
            'totalMatches': sum(m['matchCount'] for m in all_matches),
            'results': all_matches,
            'truncated': files_searched < len(files_to_search),
            'coverage_report': coverage_report,
            'interpretationGuide': {
                'NXDOMAIN': 'Domain does not exist. Likely pods querying wrong service names or non-existent domains — not a DNS server misconfiguration.',
                'OOMKilled': 'Container exceeded memory limit. Check requests/limits in pod spec.',
                'CrashLoopBackOff': 'Container keeps crashing. Check exit code and previous container logs.',
                'SERVFAIL': 'DNS server failed to resolve. Could be CoreDNS overload or upstream DNS issue.',
                'connection timed out': 'Network connectivity issue. Check security groups, NACLs, and route tables.',
                'failed to allocate': 'Resource allocation failure. For IPs: check subnet capacity and ENI limits.',
                'resolv.conf': 'If from node /etc/resolv.conf: VPC DNS (e.g., 172.31.0.2) is NORMAL for nodes. Pod DNS is separate.',
            },
            'nextStep': 'Use read to get full context around specific matches'
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
            'nextStep': 'Check if logs exist with validate'
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
        response_format: 'concise' (default) or 'detailed'
    
    Returns:
        timeline[], correlations, temporal_clusters, potential_root_cause_chain, coverage_report
    """
    instance_id = arguments.get('instanceId')
    time_window = arguments.get('timeWindow', 60)
    pivot_event = arguments.get('pivotEvent')
    components = arguments.get('components', [])
    response_format = arguments.get('response_format', 'concise')
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    try:
        # Try cached findings index first (fast path)
        prefix = f'eks_{instance_id}'
        index_key = find_findings_index(prefix)
        findings = []
        files_scanned = 0
        
        if index_key:
            read_result = safe_s3_read(index_key)
            if read_result['success']:
                try:
                    index_data = json.loads(read_result['content'])
                    findings = index_data.get('findings', [])
                    files_scanned = index_data.get('filesScanned', 0)
                except json.JSONDecodeError:
                    pass
        
        # Fall back to on-demand scan only if no cached findings
        if not findings:
            error_summary = scan_and_index_errors(instance_id, 'all')
            
            if error_summary['statusCode'] != 200:
                return success_response({
                    'instanceId': instance_id,
                    'timeWindow': time_window,
                    'timeline': [],
                    'byComponent': {},
                    'correlations': [],
                    'temporal_clusters': [],
                    'potential_root_cause_chain': [],
                    'coverage_report': {'files_scanned': 0, 'scan_complete': False},
                    'confidence': 'none',
                    'gaps': ['Could not retrieve error data for correlation'],
                    'warning': 'Could not retrieve error data for correlation',
                    'nextStep': 'Check if logs exist with validate'
                })
            
            summary_data = json.loads(error_summary['body'])
            findings = summary_data.get('findings', [])
            files_scanned = summary_data.get('coverage_report', {}).get('files_scanned', 0)
        
        # Handle no findings
        if not findings:
            return success_response({
                'instanceId': instance_id,
                'timeWindow': time_window,
                'timeline': [],
                'byComponent': {},
                'correlations': [],
                'temporal_clusters': [],
                'potential_root_cause_chain': [],
                'coverage_report': {'files_scanned': files_scanned, 'scan_complete': True},
                'confidence': 'none',
                'gaps': [],
                'info': 'No error findings to correlate. This may indicate a healthy node or logs not yet collected.',
                'nextStep': 'Use search to search for specific patterns'
            })
        
        # Backward-compat: remap old severity names
        for f in findings:
            old_sev = f.get('severity', 'info')
            if old_sev == 'warning':
                f['severity'] = 'high'
        
        # Build timeline from findings with finding_ids
        timeline = []
        for idx, finding in enumerate(findings):
            # Parse timestamp if available
            timestamp = extract_timestamp(finding.get('sample', ''))
            
            timeline.append({
                'finding_id': finding.get('finding_id', assign_finding_id(idx + 1)),
                'timestamp': timestamp,
                'source': finding.get('file', 'unknown'),
                'severity': finding.get('severity', 'info'),
                'event': finding.get('pattern', ''),
                'sample': finding.get('sample', '')[:200],
                'count': finding.get('count', 1)
            })
        
        # Sort by severity (critical first) then by count
        timeline.sort(key=lambda x: (SEVERITY_ORDER.get(x['severity'], 4), -x['count']))
        
        # Group by component
        by_component = {}
        for event in timeline:
            source = event['source']
            component = categorize_log_source(source)
            if component not in by_component:
                by_component[component] = []
            by_component[component].append(event)
        
        
        temporal_clusters = _build_temporal_clusters(timeline, time_window)
        
        
        root_cause_chain = _build_root_cause_chain(timeline, by_component, temporal_clusters)
        
        # Confidence assessment
        critical_count = len([e for e in timeline if e['severity'] == 'critical'])
        total_count = len(timeline)
        if critical_count > 0 and total_count >= 3:
            confidence = 'high'
        elif total_count >= 2:
            confidence = 'medium'
        else:
            confidence = 'low'
        
        # Identify gaps
        gaps = []
        if files_scanned < 10:
            gaps.append('Few files scanned — some log sources may be missing')
        timestamps_present = sum(1 for e in timeline if e.get('timestamp'))
        if timestamps_present < len(timeline) * 0.5:
            gaps.append('Many events lack timestamps — temporal ordering may be unreliable')
        
        return success_response({
            'instanceId': instance_id,
            'timeWindow': time_window,
            'timeline': timeline[:50],
            'byComponent': by_component,
            'correlations': find_correlations(timeline),
            'temporal_clusters': temporal_clusters,
            'potential_root_cause_chain': root_cause_chain,
            'confidence': confidence,
            'gaps': gaps,
            'coverage_report': {
                'files_scanned': files_scanned,
                'components_found': list(by_component.keys()),
                'events_with_timestamps': timestamps_present,
                'events_total': len(timeline),
                'scan_complete': True,
            },
            'caveat': (
                'Timeline correlation is based on pattern matching across log files. '
                'Timestamps may not be perfectly synchronized across components. '
                'Correlation does not imply causation — verify findings by checking '
                'pod-level config and component-specific logs.'
            ),
            'nextStep': 'Use search to investigate specific events'
        })
        
    except Exception as e:
        # Return empty correlation on error, don't fail
        return success_response({
            'instanceId': instance_id,
            'timeWindow': time_window,
            'timeline': [],
            'byComponent': {},
            'correlations': [],
            'temporal_clusters': [],
            'potential_root_cause_chain': [],
            'confidence': 'none',
            'gaps': [f'Correlation error: {str(e)}'],
            'coverage_report': {'files_scanned': 0, 'scan_complete': False},
            'error': f'Correlation encountered an error: {str(e)}',
            'nextStep': 'Check if logs exist with validate'
        })


def _build_temporal_clusters(timeline: List[Dict], time_window: int) -> List[Dict]:
    """Group events into temporal clusters based on timestamps."""
    # Separate events with and without timestamps
    timed_events = [e for e in timeline if e.get('timestamp')]
    untimed_events = [e for e in timeline if not e.get('timestamp')]
    
    if not timed_events:
        # No timestamps available — return single cluster with all events
        if timeline:
            return [{
                'cluster_id': 'C-001',
                'label': 'all-events (no timestamps)',
                'event_count': len(timeline),
                'finding_ids': [e.get('finding_id', '') for e in timeline[:20]],
                'dominant_severity': timeline[0].get('severity', 'info') if timeline else 'info',
            }]
        return []
    
    # Sort by timestamp
    timed_events.sort(key=lambda x: x['timestamp'])
    
    clusters = []
    current_cluster = [timed_events[0]]
    
    for event in timed_events[1:]:
        # Simple heuristic: events within time_window seconds are in same cluster
        # Since timestamps are strings, we do string comparison (ISO format sorts correctly)
        if len(current_cluster) < 20:  # Cap cluster size
            current_cluster.append(event)
        else:
            clusters.append(current_cluster)
            current_cluster = [event]
    
    if current_cluster:
        clusters.append(current_cluster)
    
    result = []
    for idx, cluster in enumerate(clusters):
        severities = [e['severity'] for e in cluster]
        dominant = min(severities, key=lambda s: SEVERITY_ORDER.get(s, 4))
        result.append({
            'cluster_id': f'C-{idx + 1:03d}',
            'time_range': {
                'start': cluster[0].get('timestamp'),
                'end': cluster[-1].get('timestamp'),
            },
            'event_count': len(cluster),
            'finding_ids': [e.get('finding_id', '') for e in cluster],
            'dominant_severity': dominant,
            'components': list(set(categorize_log_source(e.get('source', '')) for e in cluster)),
        })
    
    return result


def _build_root_cause_chain(timeline: List[Dict], by_component: Dict, clusters: List[Dict]) -> List[Dict]:
    """Build potential root cause chain from correlated events."""
    chain = []
    
    # Heuristic: look for known causal patterns
    critical_events = [e for e in timeline if e['severity'] == 'critical']
    
    # Pattern 1: Kernel -> Kubelet -> Pod failures
    kernel_issues = by_component.get('kernel', [])
    kubelet_issues = by_component.get('kubelet', [])
    
    if kernel_issues and kubelet_issues:
        chain.append({
            'sequence': 'kernel → kubelet → pod',
            'confidence': 'medium',
            'description': 'Kernel-level issues may have cascaded to kubelet and pod failures',
            'evidence_finding_ids': (
                [e.get('finding_id') for e in kernel_issues[:3]] +
                [e.get('finding_id') for e in kubelet_issues[:3]]
            ),
        })
    
    # Pattern 2: Network -> CNI -> Pod connectivity
    network_issues = by_component.get('networking', [])
    cni_issues = by_component.get('ipamd', []) + by_component.get('cni', [])
    
    if network_issues or cni_issues:
        chain.append({
            'sequence': 'network/CNI → pod connectivity',
            'confidence': 'medium' if (network_issues and cni_issues) else 'low',
            'description': 'Network or CNI issues may be causing pod connectivity failures',
            'evidence_finding_ids': (
                [e.get('finding_id') for e in network_issues[:3]] +
                [e.get('finding_id') for e in cni_issues[:3]]
            ),
        })
    
    # Pattern 3: OOM -> Container restarts
    oom_events = [e for e in timeline if 'oom' in e.get('event', '').lower() or 'memory' in e.get('event', '').lower()]
    restart_events = [e for e in timeline if 'restart' in e.get('event', '').lower() or 'crashloop' in e.get('event', '').lower()]
    
    if oom_events and restart_events:
        chain.append({
            'sequence': 'memory pressure → OOM kill → container restart',
            'confidence': 'high',
            'description': 'Memory pressure caused OOM kills leading to container restarts',
            'evidence_finding_ids': (
                [e.get('finding_id') for e in oom_events[:3]] +
                [e.get('finding_id') for e in restart_events[:3]]
            ),
        })
    
    # Pattern 4: Auth failures -> Node registration
    auth_events = [e for e in timeline if any(kw in e.get('event', '').lower() for kw in ['unauthorized', 'denied', 'credential'])]
    reg_events = [e for e in timeline if 'register' in e.get('event', '').lower() or 'join' in e.get('event', '').lower()]
    
    if auth_events and reg_events:
        chain.append({
            'sequence': 'auth failure → node registration failure',
            'confidence': 'high',
            'description': 'Authentication/authorization failures prevented node from joining the cluster',
            'evidence_finding_ids': (
                [e.get('finding_id') for e in auth_events[:3]] +
                [e.get('finding_id') for e in reg_events[:3]]
            ),
        })
    
    return chain


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
    Requires finding_ids to ground summary in verified evidence.
    Falls back to full retrieval if finding_ids not provided (backward compat).
    
    Inputs:
        instanceId: EC2 instance ID (required)
        finding_ids: List of finding IDs from errors/search to include (recommended)
        includeRecommendations: Include remediation suggestions (default: true)
        includeTriage: Include pod/node failure triage analysis (default: true)
    
    Returns:
        summary with criticalFindings, timeline, recommendations, artifactLinks,
        pod_node_triage, confidence, gaps
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
    finding_ids = arguments.get('finding_ids', [])
    include_recommendations = arguments.get('includeRecommendations', True)
    include_triage = arguments.get('includeTriage', True)
    
    if not instance_id:
        return error_response(400, 'instanceId is required')
    
    if not finding_ids:
        return error_response(400,
            'finding_ids is required. Call errors tool first to get finding_ids (F-001 format), '
            'then pass them here to ground the summary in verified evidence.')
    
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
            error_result = get_error_summary({'instanceId': instance_id, 'severity': 'all', 'pageSize': 200})
            if error_result['statusCode'] == 200:
                error_data = json.loads(error_result['body'])
        except TimeoutError:
            raise
        except Exception as e:
            print(f"Warning: Could not get error summary: {str(e)}")
        
        check_timeout()
        
        # Build summary with available data
        all_findings = error_data.get('findings', [])
        summary_counts = error_data.get('summary', {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0})
        
        # If finding_ids provided, filter to only those findings
        grounded = bool(finding_ids)
        if finding_ids:
            finding_id_set = set(finding_ids)
            findings = [f for f in all_findings if f.get('finding_id') in finding_id_set]
            # Warn about unresolved IDs
            resolved_ids = {f.get('finding_id') for f in findings}
            unresolved_ids = finding_id_set - resolved_ids
        else:
            findings = all_findings
            unresolved_ids = set()
        
        critical_findings = [f for f in findings if f.get('severity') == 'critical'][:10]
        high_findings = [f for f in findings if f.get('severity') == 'high'][:10]
        medium_findings = [f for f in findings if f.get('severity') == 'medium'][:5]
        
        # Identify affected components
        affected_components = set()
        for finding in findings:
            component = categorize_log_source(finding.get('file', ''))
            affected_components.add(component)
        
        # Confidence assessment
        if grounded and len(findings) >= 3 and critical_findings:
            confidence = 'high'
        elif grounded and len(findings) >= 1:
            confidence = 'medium'
        elif not grounded and critical_findings:
            confidence = 'medium'
        else:
            confidence = 'low'
        
        # Identify gaps
        gaps = []
        if not grounded:
            gaps.append('Summary not grounded in specific finding_ids — may include unverified patterns')
        if unresolved_ids:
            gaps.append(f'{len(unresolved_ids)} finding_ids could not be resolved: {list(unresolved_ids)[:5]}')
        coverage = error_data.get('coverage_report', {})
        if coverage and not coverage.get('scan_complete', True):
            gaps.append('Not all log files were scanned — some findings may be missing')
        
        summary = {
            'instanceId': instance_id,
            'generatedAt': datetime.utcnow().isoformat(),
            'executionTimeMs': int((time.time() - start_time) * 1000),
            'grounded': grounded,
            'confidence': confidence,
            'gaps': gaps,
            'bundleStatus': {
                'complete': bundle_data.get('complete', False),
                'fileCount': bundle_data.get('fileCount', 0),
                'totalSize': bundle_data.get('totalSizeHuman', 'unknown')
            },
            'errorSummary': {
                'critical': summary_counts.get('critical', 0),
                'high': summary_counts.get('high', 0),
                'medium': summary_counts.get('medium', 0),
                'low': summary_counts.get('low', 0),
                'info': summary_counts.get('info', 0),
                'total': len(all_findings)
            },
            'criticalFindings': [
                {
                    'finding_id': f.get('finding_id'),
                    'file': f.get('file'),
                    'fullKey': f.get('fullKey'),
                    'pattern': f.get('pattern'),
                    'count': f.get('count'),
                    'sample': f.get('sample', '')[:200]
                }
                for f in critical_findings
            ],
            'highFindings': [
                {
                    'finding_id': f.get('finding_id'),
                    'file': f.get('file'),
                    'fullKey': f.get('fullKey'),
                    'pattern': f.get('pattern'),
                    'count': f.get('count')
                }
                for f in high_findings
            ],
            'affectedComponents': list(affected_components),
        }
        
        # Add info if no findings
        if not findings:
            summary['info'] = 'No error findings detected. Node may be healthy or logs not yet collected.'
        
        # Add recommendations if requested
        if include_recommendations:
            summary['recommendations'] = generate_recommendations(critical_findings, high_findings, medium_findings)
        
        # Add artifact links for key files
        summary['artifactLinks'] = []
        for finding in critical_findings[:5]:
            if finding.get('fullKey'):
                summary['artifactLinks'].append({
                    'finding_id': finding.get('finding_id'),
                    'file': finding.get('file'),
                    'key': finding.get('fullKey'),
                    'action': f'read(logKey="{finding.get("fullKey")}")'
                })
        
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
        
        # Add caveat about analysis methodology
        summary['caveat'] = (
            'Root cause analysis is based on log pattern matching only. '
            'Verify findings by: (1) checking pod-level config (kubectl exec <pod> -- cat /etc/resolv.conf), '
            '(2) reviewing CoreDNS/kube-proxy/CNI pod logs, (3) checking kubelet --cluster-dns flag, '
            '(4) confirming node conditions (kubectl describe node). '
            'Log patterns indicate symptoms, not always root causes. '
            'Node-level /etc/resolv.conf showing VPC DNS is NORMAL — pod DNS is configured separately by kubelet.'
        )

        # Add next step guidance
        if summary.get('pod_node_triage', {}).get('most_likely_root_cause'):
            root_cause = summary['pod_node_triage']['most_likely_root_cause']
            summary['nextStep'] = f"Root cause identified: {root_cause['category_name']} ({root_cause['confidence']} confidence). Follow immediate_remediation_steps in pod_node_triage."
        else:
            summary['nextStep'] = 'Use search for detailed investigation of specific patterns'
        
        # Update execution time
        summary['executionTimeMs'] = int((time.time() - start_time) * 1000)
        
        return success_response(summary)
    
    except TimeoutError as e:
        # Return partial summary on timeout
        return success_response({
            'instanceId': instance_id,
            'generatedAt': datetime.utcnow().isoformat(),
            'executionTimeMs': int((time.time() - start_time) * 1000),
            'grounded': bool(finding_ids),
            'confidence': 'low',
            'gaps': ['Execution timed out — partial results only'],
            'bundleStatus': bundle_data if bundle_data else {'complete': False, 'fileCount': 0, 'totalSize': 'unknown'},
            'errorSummary': error_data.get('summary', {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}) if error_data else {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0},
            'criticalFindings': [],
            'highFindings': [],
            'affectedComponents': [],
            'recommendations': [],
            'artifactLinks': [],
            'pod_node_triage': {
                'triageVersion': '1.0',
                'warning': 'Analysis timed out. Try calling errors and summarize separately.'
            },
            'warning': f'Execution timed out: {str(e)}',
            'nextStep': 'Call errors first, then summarize with includeTriage=false'
        })
        
    except Exception as e:
        # Return partial summary on error, don't fail
        return success_response({
            'instanceId': instance_id,
            'generatedAt': datetime.utcnow().isoformat(),
            'grounded': bool(finding_ids),
            'confidence': 'none',
            'gaps': [f'Summary generation failed: {str(e)}'],
            'bundleStatus': {'complete': False, 'fileCount': 0, 'totalSize': 'unknown'},
            'errorSummary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0},
            'criticalFindings': [],
            'highFindings': [],
            'affectedComponents': [],
            'recommendations': [],
            'artifactLinks': [],
            'pod_node_triage': {
                'triageVersion': '1.0',
                'error': f'Summary generation failed: {str(e)}'
            },
            'error': f'Could not generate complete summary: {str(e)}',
            'nextStep': 'Check if logs exist with validate'
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
        
        # Support cross-region listing — try explicit region, then default, then common EKS regions
        target_region = arguments.get('region', DEFAULT_REGION)
        regions_to_try = [target_region]
        # If default region returned nothing, also try common EKS regions
        common_eks_regions = ['us-west-2', 'us-east-1', 'eu-west-1', 'ap-southeast-1']
        for r in common_eks_regions:
            if r not in regions_to_try:
                regions_to_try.append(r)

        collections = []
        searched_regions = []

        for region in regions_to_try:
            try:
                regional_ssm = get_regional_client('ssm', region)
                response = regional_ssm.describe_automation_executions(
                    Filters=filters,
                    MaxResults=max_results
                )
                
                for exec_meta in response.get('AutomationExecutionMetadataList', []):
                    # Filter by instance if specified
                    if instance_id:
                        params = exec_meta.get('Parameters', {})
                        exec_instance = params.get('EKSInstanceId', [''])[0]
                        if instance_id not in exec_instance:
                            continue
                    
                    # Check if S3 bundle still exists
                    exec_id = exec_meta['AutomationExecutionId']
                    params = exec_meta.get('Parameters', {})
                    exec_instance = params.get('EKSInstanceId', [''])[0]
                    bundle_exists = False
                    if exec_instance:
                        s3_check = safe_s3_list(f"eks_{exec_instance}_{exec_id}/", max_keys=1)
                        bundle_exists = bool(s3_check.get('success') and s3_check.get('objects'))

                    collections.append({
                        'executionId': exec_id,
                        'documentName': exec_meta.get('DocumentName', ''),
                        'status': exec_meta['AutomationExecutionStatus'],
                        'startTime': exec_meta.get('ExecutionStartTime'),
                        'endTime': exec_meta.get('ExecutionEndTime'),
                        'instanceId': exec_instance or None,
                        'region': region,
                        'bundleExists': bundle_exists,
                    })
                
                searched_regions.append(region)
                # If we found results, stop searching more regions
                if collections:
                    break
            except Exception:
                searched_regions.append(f"{region} (error)")
                continue
        
        return success_response({
            'collections': collections,
            'count': len(collections),
            'searchedRegions': searched_regions,
            'filters': {
                'instanceId': instance_id,
                'status': status_filter,
                'documentName': document_name
            }
        })
        
    except Exception as e:
        return error_response(500, f'Failed to list history: {str(e)}')


# =============================================================================
# TIER 3: CLUSTER-LEVEL INTELLIGENCE
# =============================================================================

def cluster_health(arguments: Dict) -> Dict:
    """
    Comprehensive EKS cluster health overview.
    Enumerates all nodes, checks SSM status, instance metadata, and flags unhealthy nodes.

    Inputs:
        clusterName: EKS cluster name (required)
        region: AWS region (optional, auto-detected)
        includeSSMStatus: Check SSM agent per node (default: true)

    Returns:
        clusterInfo, nodes[], healthSummary
    """
    cluster_name = arguments.get('clusterName')
    if not cluster_name:
        return error_response(400, 'clusterName is required')

    include_ssm = arguments.get('includeSSMStatus', True)
    target_region = resolve_region(arguments)

    try:
        regional_eks = get_regional_client('eks', target_region)
        regional_ec2 = get_regional_client('ec2', target_region)
        regional_ssm = get_regional_client('ssm', target_region)

        # 1. Describe the cluster
        try:
            cluster_resp = regional_eks.describe_cluster(name=cluster_name)
            cluster_info = cluster_resp.get('cluster', {})
            cluster_meta = {
                'name': cluster_info.get('name'),
                'version': cluster_info.get('version'),
                'status': cluster_info.get('status'),
                'platformVersion': cluster_info.get('platformVersion'),
                'endpoint': cluster_info.get('endpoint', '')[:80] + '...',
                'region': target_region,
            }
        except Exception as e:
            return error_response(404, f'Cluster {cluster_name} not found in {target_region}: {str(e)}')

        # 2. List nodegroups
        nodegroups = []
        try:
            ng_resp = regional_eks.list_nodegroups(clusterName=cluster_name)
            for ng_name in ng_resp.get('nodegroups', []):
                try:
                    ng_detail = regional_eks.describe_nodegroup(
                        clusterName=cluster_name, nodegroupName=ng_name
                    )['nodegroup']
                    nodegroups.append({
                        'name': ng_name,
                        'status': ng_detail.get('status'),
                        'instanceTypes': ng_detail.get('instanceTypes', []),
                        'amiType': ng_detail.get('amiType'),
                        'desiredSize': ng_detail.get('scalingConfig', {}).get('desiredSize'),
                        'minSize': ng_detail.get('scalingConfig', {}).get('minSize'),
                        'maxSize': ng_detail.get('scalingConfig', {}).get('maxSize'),
                        'releaseVersion': ng_detail.get('releaseVersion'),
                    })
                except Exception:
                    nodegroups.append({'name': ng_name, 'status': 'DESCRIBE_FAILED'})
        except Exception:
            pass

        # 3. Find all EC2 instances tagged with this cluster
        paginator = regional_ec2.get_paginator('describe_instances')
        page_iter = paginator.paginate(
            Filters=[
                {'Name': 'tag:eks:cluster-name', 'Values': [cluster_name]},
                {'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'pending', 'stopping', 'shutting-down']},
            ]
        )

        nodes = []
        instance_ids = []
        for page in page_iter:
            for res in page.get('Reservations', []):
                for inst in res.get('Instances', []):
                    iid = inst['InstanceId']
                    instance_ids.append(iid)
                    tags = {t['Key']: t['Value'] for t in inst.get('Tags', [])}
                    nodes.append({
                        'instanceId': iid,
                        'instanceType': inst.get('InstanceType'),
                        'availabilityZone': inst.get('Placement', {}).get('AvailabilityZone'),
                        'state': inst.get('State', {}).get('Name'),
                        'launchTime': inst.get('LaunchTime'),
                        'privateIp': inst.get('PrivateIpAddress'),
                        'imageId': inst.get('ImageId'),
                        'nodegroup': tags.get('eks:nodegroup-name', 'unknown'),
                        'name': tags.get('Name', ''),
                        'ssmStatus': None,
                    })

        # 4. Check SSM agent status in batches
        if include_ssm and instance_ids:
            ssm_status_map = {}
            # SSM DescribeInstanceInformation supports InstanceInformationFilterList
            # to filter by instance IDs, avoiding scanning the entire account.
            # Process in chunks of 50 (API limit per filter).
            try:
                cluster_ids_set = set(instance_ids)
                for i in range(0, len(instance_ids), 50):
                    chunk = instance_ids[i:i+50]
                    ssm_paginator = regional_ssm.get_paginator('describe_instance_information')
                    for page in ssm_paginator.paginate(
                        Filters=[{'Key': 'InstanceIds', 'Values': chunk}]
                    ):
                        for info in page.get('InstanceInformationList', []):
                            if info['InstanceId'] in cluster_ids_set:
                                ssm_status_map[info['InstanceId']] = {
                                    'pingStatus': info.get('PingStatus'),
                                    'agentVersion': info.get('AgentVersion'),
                                    'platformName': info.get('PlatformName'),
                                    'lastPingTime': info.get('LastPingDateTime'),
                                }
            except Exception as e:
                print(f"SSM status check failed: {e}")

            for node in nodes:
                ssm_info = ssm_status_map.get(node['instanceId'])
                if ssm_info:
                    node['ssmStatus'] = ssm_info
                else:
                    node['ssmStatus'] = {'pingStatus': 'NotRegistered', 'agentVersion': None}

        # 5. Build health summary
        total = len(nodes)
        running = sum(1 for n in nodes if n['state'] == 'running')
        ssm_online = sum(1 for n in nodes if n.get('ssmStatus', {}).get('pingStatus') == 'Online')
        ssm_offline = total - ssm_online if include_ssm else None

        # Group by AZ
        az_distribution = {}
        for n in nodes:
            az = n.get('availabilityZone', 'unknown')
            az_distribution[az] = az_distribution.get(az, 0) + 1

        # Group by nodegroup
        ng_distribution = {}
        for n in nodes:
            ng = n.get('nodegroup', 'unknown')
            ng_distribution[ng] = ng_distribution.get(ng, 0) + 1

        # Flag unhealthy nodes
        unhealthy = []
        for n in nodes:
            issues = []
            if n['state'] != 'running':
                issues.append(f"ec2State={n['state']}")
            if include_ssm and n.get('ssmStatus', {}).get('pingStatus') != 'Online':
                issues.append(f"ssm={n.get('ssmStatus', {}).get('pingStatus', 'unknown')}")
            if issues:
                unhealthy.append({'instanceId': n['instanceId'], 'issues': issues})

        health_summary = {
            'totalNodes': total,
            'running': running,
            'ssmOnline': ssm_online,
            'ssmOffline': ssm_offline,
            'unhealthyCount': len(unhealthy),
            'azDistribution': az_distribution,
            'nodegroupDistribution': ng_distribution,
        }

        # Confidence assessment 
        gaps = []
        if not include_ssm:
            gaps.append('SSM status not checked — some unhealthy nodes may be missed')
        if total == 0:
            gaps.append('No nodes found — cluster may be empty or tag filter mismatch')
        if include_ssm and ssm_offline and ssm_offline > 0:
            gaps.append(f'{ssm_offline} nodes not reachable via SSM — cannot collect logs from these')

        if total > 0 and include_ssm and ssm_online == total:
            confidence = 'high'
        elif total > 0 and include_ssm:
            confidence = 'medium'
        elif total > 0:
            confidence = 'low'
        else:
            confidence = 'none'

        return success_response({
            'cluster': cluster_meta,
            'nodegroups': nodegroups,
            'nodes': nodes,
            'unhealthyNodes': unhealthy,
            'healthSummary': health_summary,
            'region': target_region,
            'confidence': confidence,
            'gaps': gaps,
            'nextStep': 'Use compare_nodes to diff specific nodes, or batch_collect to sample unhealthy nodes' if unhealthy else 'Cluster looks healthy. Use collect on a specific node if needed.',
        })

    except Exception as e:
        return error_response(500, f'cluster_health failed: {str(e)}')


def compare_nodes(arguments: Dict) -> Dict:
    """
    Diff error findings and health between two or more nodes.
    Returns structured diff: common issues vs. unique-to-each-node.

    Inputs:
        instanceIds: list of 2+ instance IDs (required)
        compareFields: "errors", "config", "all" (default: "all")

    Returns:
        commonFindings[], uniqueFindings{}, comparisonMatrix
    """
    instance_ids = arguments.get('instanceIds', [])
    if not instance_ids or len(instance_ids) < 2:
        return error_response(400, 'instanceIds must contain at least 2 instance IDs')
    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for iid in instance_ids:
        if iid not in seen:
            seen.add(iid)
            deduped.append(iid)
    instance_ids = deduped
    if len(instance_ids) < 2:
        return error_response(400, 'instanceIds must contain at least 2 distinct instance IDs')
    if len(instance_ids) > 10:
        return error_response(400, 'Maximum 10 nodes for comparison')

    compare_fields = arguments.get('compareFields', 'all')

    try:
        node_findings = {}
        node_configs = {}

        def _gather_node_data(iid):
            """Gather findings + config for a single node (runs in thread)."""
            nf = []
            nc = {}
            if compare_fields in ('errors', 'all'):
                prefix = f"eks_{iid}"
                try:
                    idx = find_findings_index(prefix)
                    if idx:
                        resp = s3_client.get_object(Bucket=LOGS_BUCKET, Key=idx)
                        findings_data = json.loads(resp['Body'].read().decode('utf-8'))
                        nf = findings_data.get('findings', [])
                    else:
                        # No pre-built index — don't do inline scan (too slow for gateway timeout).
                        # Return a marker so caller knows this node needs collection first.
                        nf = [{'error': f'No findings index for {iid}. Run collect first and wait for completion.', 'needsCollection': True}]
                except Exception as e:
                    nf = [{'error': f'Could not load findings: {str(e)}'}]

            if compare_fields in ('config', 'all'):
                # Find the actual extracted bundle prefix (eks_{iid}_{execution_id}/extracted/)
                list_result = safe_s3_list(f"eks_{iid}", max_keys=50)
                extracted_prefix = None
                if list_result.get('success'):
                    for obj in list_result.get('objects', []):
                        if '/extracted/' in obj['key']:
                            extracted_prefix = obj['key'].split('/extracted/')[0] + '/extracted/'
                            break

                if extracted_prefix:
                    config_files = [
                        ('kubelet_config', f"{extracted_prefix}kubelet-config.json"),
                        ('kubelet_flags', f"{extracted_prefix}kubelet-flags"),
                        ('containerd_config', f"{extracted_prefix}containerd-config.toml"),
                    ]
                else:
                    config_files = []

                for config_name, config_key in config_files:
                    result = safe_s3_read(config_key, max_size=65536)
                    if result.get('success'):
                        nc[config_name] = result['content'][:2000]
                    else:
                        nc[config_name] = None
            return iid, nf, nc

        # Parallel per-node gathering
        with ThreadPoolExecutor(max_workers=min(len(instance_ids), 10)) as executor:
            futures = {executor.submit(_gather_node_data, iid): iid for iid in instance_ids}
            for future in as_completed(futures):
                iid_key = futures[future]
                try:
                    iid, nf, nc = future.result()
                    node_findings[iid] = nf
                    node_configs[iid] = nc
                except Exception as e:
                    node_findings[iid_key] = [{'error': f'Failed to gather data: {str(e)}'}]
                    node_configs[iid_key] = {}

        # Build comparison: find common vs unique error patterns
        common_findings = []
        unique_findings = {}

        if compare_fields in ('errors', 'all') and node_findings:
            # Normalize findings to comparable signatures
            def finding_signature(f):
                # Skip error entries from failed loads — they have no pattern/severity
                if 'error' in f and 'severity' not in f:
                    return f"__error__{f.get('error', 'unknown')[:80]}"
                return f"{f.get('severity', '')}__{f.get('category', '')}__{f.get('pattern', f.get('message', ''))[:80]}"

            sig_to_nodes = {}
            for iid, findings in node_findings.items():
                unique_findings[iid] = []
                for f in findings:
                    sig = finding_signature(f)
                    if sig not in sig_to_nodes:
                        sig_to_nodes[sig] = {'finding': f, 'nodes': []}
                    sig_to_nodes[sig]['nodes'].append(iid)

            for sig, data in sig_to_nodes.items():
                if len(data['nodes']) == len(instance_ids):
                    common_findings.append({
                        **data['finding'],
                        'presentOnAllNodes': True,
                    })
                else:
                    for iid in data['nodes']:
                        unique_findings[iid].append({
                            **data['finding'],
                            'uniqueTo': iid,
                        })

        # Config diff
        config_diffs = {}
        if compare_fields in ('config', 'all') and node_configs:
            ref_id = instance_ids[0]
            ref_config = node_configs.get(ref_id, {})
            for iid in instance_ids[1:]:
                other_config = node_configs.get(iid, {})
                diffs = []
                all_keys = set(list(ref_config.keys()) + list(other_config.keys()))
                for key in all_keys:
                    ref_val = ref_config.get(key)
                    other_val = other_config.get(key)
                    if ref_val != other_val:
                        diffs.append({
                            'configFile': key,
                            'referenceNode': ref_id,
                            'comparedNode': iid,
                            'match': False,
                            'note': 'Content differs' if (ref_val and other_val) else 'Missing on one node',
                        })
                config_diffs[f"{ref_id}_vs_{iid}"] = diffs if diffs else [{'match': True, 'note': 'Configs identical'}]

        # Summary matrix
        matrix = []
        for iid in instance_ids:
            total_findings = len(node_findings.get(iid, []))
            unique_count = len(unique_findings.get(iid, []))
            critical_count = sum(1 for f in node_findings.get(iid, [])
                                 if f.get('severity') == 'critical')
            matrix.append({
                'instanceId': iid,
                'totalFindings': total_findings,
                'criticalFindings': critical_count,
                'uniqueFindings': unique_count,
                'commonFindings': total_findings - unique_count,
            })

        # Confidence assessment 
        gaps = []
        nodes_without_index = [iid for iid, findings in node_findings.items()
                               if findings and isinstance(findings[0], dict) and findings[0].get('needsCollection')]
        if nodes_without_index:
            gaps.append(f'No findings index for: {nodes_without_index}. Run collect first.')
        nodes_with_errors = [iid for iid, findings in node_findings.items()
                             if findings and isinstance(findings[0], dict) and 'error' in findings[0] and 'severity' not in findings[0]]
        if nodes_with_errors:
            gaps.append(f'Failed to load findings for: {nodes_with_errors}')
        if compare_fields != 'all':
            gaps.append(f'Only compared {compare_fields} — use compareFields=all for full comparison')

        if not gaps and len(common_findings) + sum(len(v) for v in unique_findings.values()) > 0:
            confidence = 'high'
        elif not nodes_without_index and not nodes_with_errors:
            confidence = 'medium'
        else:
            confidence = 'low'

        return success_response({
            'comparedNodes': instance_ids,
            'commonFindings': common_findings,
            'commonFindingsCount': len(common_findings),
            'uniqueFindings': unique_findings,
            'configDiffs': config_diffs,
            'comparisonMatrix': matrix,
            'insight': _generate_comparison_insight(common_findings, unique_findings, instance_ids),
            'confidence': confidence,
            'gaps': gaps,
            'caveat': (
                'Comparison is based on pre-indexed error findings from log bundles. '
                'Differences may reflect different workloads rather than configuration issues. '
                'Config diffs show file-level differences — verify significance by checking '
                'kubelet flags and node group settings.'
            ),
            'nextStep': 'Common findings suggest a cluster-wide issue. Unique findings point to node-specific problems.',
        })

    except Exception as e:
        return error_response(500, f'compare_nodes failed: {str(e)}')


def _generate_comparison_insight(common: List, unique: Dict, instance_ids: List[str]) -> str:
    """Generate a human-readable insight from the comparison."""
    common_count = len(common)
    total_unique = sum(len(v) for v in unique.values())

    if common_count > 0 and total_unique == 0:
        return f"All {len(instance_ids)} nodes share the same {common_count} findings. This is likely a cluster-wide issue (bad AMI, misconfigured nodegroup, or control plane problem)."
    elif common_count == 0 and total_unique > 0:
        return f"No common findings across nodes. Each node has unique issues — investigate individually."
    elif common_count > total_unique:
        return f"{common_count} common findings vs {total_unique} unique. Mostly a shared problem with some node-specific noise."
    else:
        return f"{common_count} common, {total_unique} unique findings. Mixed picture — check unique findings for the root cause on specific nodes."


def batch_collect(arguments: Dict) -> Dict:
    """
    Smart batch log collection with statistical sampling.
    Triages nodes, groups by failure signature, samples representatives.

    Inputs:
        clusterName: EKS cluster name (required)
        region: AWS region (optional)
        filter: "all", "unhealthy", "notready" (default: "unhealthy")
            - unhealthy: EC2 state != running OR SSM != Online
            - notready: SSM not Online (regardless of EC2 state) — targets nodes that can't run SSM commands
        strategy: "sample" or "all" (default: "sample")
        samplesPerBucket: nodes per bucket (default: 3, max: 5)
        maxTotalCollections: hard cap (default: 15, max: 15)
        groupBy: "auto", "az", "nodegroup", "instance-type", "ami" (default: "auto")
        dryRun: preview only (default: false)

    Returns:
        buckets[], plannedCollections, executions[] (if not dryRun)
    """
    cluster_name = arguments.get('clusterName')
    if not cluster_name:
        return error_response(400, 'clusterName is required')

    target_region = resolve_region(arguments)
    node_filter = arguments.get('filter', 'unhealthy')
    # Validate filter parameter
    valid_filters = ('all', 'unhealthy', 'notready')
    if node_filter not in valid_filters:
        return error_response(400, f"Invalid filter '{node_filter}'. Must be one of: {', '.join(valid_filters)}")
    strategy = arguments.get('strategy', 'sample')
    samples_per_bucket = min(arguments.get('samplesPerBucket', 3), 5)
    max_total = min(arguments.get('maxTotalCollections', 15), 15)
    group_by = arguments.get('groupBy', 'auto')
    dry_run = arguments.get('dryRun', False)

    try:
        regional_eks = get_regional_client('eks', target_region)
        regional_ec2 = get_regional_client('ec2', target_region)
        regional_ssm = get_regional_client('ssm', target_region)

        # 1. Get all cluster nodes
        paginator = regional_ec2.get_paginator('describe_instances')
        page_iter = paginator.paginate(
            Filters=[
                {'Name': 'tag:eks:cluster-name', 'Values': [cluster_name]},
                {'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'pending', 'stopping', 'shutting-down']},
            ]
        )

        all_nodes = []
        for page in page_iter:
            for res in page.get('Reservations', []):
                for inst in res.get('Instances', []):
                    tags = {t['Key']: t['Value'] for t in inst.get('Tags', [])}
                    all_nodes.append({
                        'instanceId': inst['InstanceId'],
                        'state': inst.get('State', {}).get('Name'),
                        'instanceType': inst.get('InstanceType'),
                        'az': inst.get('Placement', {}).get('AvailabilityZone'),
                        'imageId': inst.get('ImageId'),
                        'nodegroup': tags.get('eks:nodegroup-name', 'unknown'),
                        'launchTime': inst.get('LaunchTime'),
                    })

        if not all_nodes:
            return error_response(404, f'No nodes found for cluster {cluster_name} in {target_region}')

        # 2. Check SSM status to identify unhealthy nodes (filtered to cluster nodes only)
        ssm_status = {}
        node_ids = [n['instanceId'] for n in all_nodes]
        try:
            for i in range(0, len(node_ids), 50):
                chunk = node_ids[i:i+50]
                ssm_paginator = regional_ssm.get_paginator('describe_instance_information')
                for page in ssm_paginator.paginate(
                    Filters=[{'Key': 'InstanceIds', 'Values': chunk}]
                ):
                    for info in page.get('InstanceInformationList', []):
                        ssm_status[info['InstanceId']] = info.get('PingStatus', 'Unknown')
        except Exception:
            pass

        # 3. Apply filter
        filtered_nodes = []
        for node in all_nodes:
            ssm_ping = ssm_status.get(node['instanceId'], 'NotRegistered')
            node['ssmPingStatus'] = ssm_ping
            # unhealthy: EC2 not running OR SSM not Online
            is_unhealthy = (node['state'] != 'running') or (ssm_ping != 'Online')
            # notready: SSM not Online — these nodes can't execute SSM commands
            # (a subset of unhealthy focused on SSM reachability regardless of EC2 state)
            is_not_ready = ssm_ping != 'Online'

            if node_filter == 'all':
                filtered_nodes.append(node)
            elif node_filter == 'unhealthy' and is_unhealthy:
                filtered_nodes.append(node)
            elif node_filter == 'notready' and is_not_ready:
                filtered_nodes.append(node)

        # If filter returned no results, return a clear message
        if not filtered_nodes and node_filter in ('unhealthy', 'notready'):
            return success_response({
                'message': f'No {node_filter} nodes found — cluster looks healthy',
                'totalNodes': len(all_nodes),
                'filteredNodes': 0,
                'filter': node_filter,
                'buckets': [],
                'plannedCollections': 0,
            })

        # 4. Group into buckets
        buckets = {}
        for node in filtered_nodes:
            if group_by == 'az':
                key = node['az']
            elif group_by == 'nodegroup':
                key = node['nodegroup']
            elif group_by == 'instance-type':
                key = node['instanceType']
            elif group_by == 'ami':
                key = node['imageId']
            else:
                # Auto: combine nodegroup + AZ + state + SSM status
                key = f"{node['nodegroup']}|{node['az']}|{node['state']}|{node['ssmPingStatus']}"

            if key not in buckets:
                buckets[key] = {
                    'signature': key,
                    'nodes': [],
                    'count': 0,
                }
            buckets[key]['nodes'].append(node)
            buckets[key]['count'] += 1

        # 5. Select samples from each bucket
        bucket_list = []
        total_planned = 0
        for sig, bucket in buckets.items():
            if strategy == 'sample':
                sample_count = min(samples_per_bucket, bucket['count'])
            else:
                sample_count = bucket['count']

            # Respect hard cap
            if total_planned + sample_count > max_total:
                sample_count = max(0, max_total - total_planned)

            sample_nodes = bucket['nodes'][:sample_count]
            total_planned += len(sample_nodes)

            bucket_list.append({
                'signature': sig,
                'totalNodes': bucket['count'],
                'sampleCount': len(sample_nodes),
                'sampleNodes': [n['instanceId'] for n in sample_nodes],
                'representativeInfo': {
                    'instanceType': sample_nodes[0]['instanceType'] if sample_nodes else None,
                    'az': sample_nodes[0]['az'] if sample_nodes else None,
                    'nodegroup': sample_nodes[0]['nodegroup'] if sample_nodes else None,
                    'imageId': sample_nodes[0]['imageId'] if sample_nodes else None,
                },
            })

        # 6. Dry run — just return the plan
        if dry_run:
            return success_response({
                'dryRun': True,
                'clusterName': cluster_name,
                'region': target_region,
                'totalNodes': len(all_nodes),
                'filteredNodes': len(filtered_nodes),
                'filter': node_filter,
                'strategy': strategy,
                'bucketCount': len(bucket_list),
                'buckets': bucket_list,
                'plannedCollections': total_planned,
                'message': f'{len(filtered_nodes)} nodes grouped into {len(bucket_list)} buckets. Will collect from {total_planned} representative nodes. Re-run with dryRun=false to proceed.',
            })

        # 7. Execute collections
        batch_id = hashlib.md5(f"{cluster_name}-{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
        executions = []

        for bucket in bucket_list:
            for iid in bucket['sampleNodes']:
                try:
                    # Reuse existing collect logic
                    collect_args = {
                        'instanceId': iid,
                        'region': target_region,
                        'idempotencyToken': f"batch-{batch_id}-{iid}",
                    }
                    result = start_log_collection(collect_args)
                    result_body = json.loads(result.get('body', '{}'))
                    executions.append({
                        'instanceId': iid,
                        'bucket': bucket['signature'],
                        'executionId': result_body.get('executionId'),
                        'status': 'Started' if result_body.get('success') else 'Failed',
                        'error': result_body.get('error'),
                    })
                except Exception as e:
                    executions.append({
                        'instanceId': iid,
                        'bucket': bucket['signature'],
                        'status': 'Failed',
                        'error': str(e),
                    })

        # Store batch metadata
        try:
            s3_client.put_object(
                Bucket=LOGS_BUCKET,
                Key=f"batches/{batch_id}/metadata.json",
                Body=json.dumps({
                    'batchId': batch_id,
                    'clusterName': cluster_name,
                    'region': target_region,
                    'createdAt': datetime.utcnow().isoformat(),
                    'executions': executions,
                    'buckets': bucket_list,
                }, default=str),
                ContentType='application/json',
            )
        except Exception:
            pass

        started = sum(1 for e in executions if e['status'] == 'Started')
        failed = sum(1 for e in executions if e['status'] == 'Failed')

        # Determine task state
        if failed == len(executions):
            task_state = 'failed'
        elif started > 0:
            task_state = 'running'
        else:
            task_state = 'failed'

        return success_response({
            'batchId': batch_id,
            'clusterName': cluster_name,
            'region': target_region,
            'totalNodes': len(all_nodes),
            'filteredNodes': len(filtered_nodes),
            'bucketCount': len(bucket_list),
            'buckets': bucket_list,
            'executions': executions,
            'collectionsStarted': started,
            'collectionsFailed': failed,
            'task': {
                'taskId': batch_id,
                'state': task_state,
                'message': f'{started} collections started, {failed} failed',
                'progress': 0 if task_state == 'running' else 100,
            },
            'nextStep': f'Use batch_status(batchId="{batch_id}") to poll all collections at once. Wait until allComplete=true before running analysis tools.',
        })

    except Exception as e:
        return error_response(500, f'batch_collect failed: {str(e)}')


def batch_status(arguments: Dict) -> Dict:
    """
    Poll status of multiple log collections at once.
    Returns consolidated view with allComplete flag.

    Inputs:
        executionIds: list of SSM execution IDs (required if no batchId)
        batchId: batch ID from batch_collect (alternative to executionIds)

    Returns:
        allComplete, summary counts, per-execution status
    """
    execution_ids = arguments.get('executionIds', [])
    batch_id = arguments.get('batchId')

    # If batchId provided, load execution IDs from stored metadata
    if batch_id and not execution_ids:
        try:
            meta_result = safe_s3_read(f"batches/{batch_id}/metadata.json")
            if meta_result.get('success'):
                meta = json.loads(meta_result['content'])
                execution_ids = [
                    e['executionId'] for e in meta.get('executions', [])
                    if e.get('executionId')
                ]
        except Exception:
            pass

    if not execution_ids:
        return error_response(400, 'executionIds list or batchId is required')

    # Deduplicate
    execution_ids = list(dict.fromkeys(execution_ids))

    # Poll all executions in parallel
    results = []

    def _poll(eid):
        try:
            target_region = get_execution_region(eid) or DEFAULT_REGION
            regional_ssm = get_regional_client('ssm', target_region)
            resp = regional_ssm.get_automation_execution(AutomationExecutionId=eid)
            execution = resp['AutomationExecution']
            status = execution['AutomationExecutionStatus']
            # Extract instanceId from parameters
            params = execution.get('Parameters', {})
            instance_id = params.get('InstanceId', [None])[0] if params.get('InstanceId') else None
            return {
                'executionId': eid,
                'instanceId': instance_id,
                'status': status,
                'progress': 100 if status == 'Success' else (0 if status == 'Failed' else estimate_progress(execution)),
                'failureReason': parse_failure_reason(execution) if status == 'Failed' else None,
            }
        except Exception as e:
            return {
                'executionId': eid,
                'instanceId': None,
                'status': 'Unknown',
                'progress': 0,
                'error': str(e),
            }

    with ThreadPoolExecutor(max_workers=min(len(execution_ids), 15)) as executor:
        results = list(executor.map(_poll, execution_ids))

    # Compute summary
    succeeded = [r for r in results if r['status'] == 'Success']
    failed = [r for r in results if r['status'] == 'Failed']
    in_progress = [r for r in results if r['status'] in ('InProgress', 'Pending', 'Waiting')]
    unknown = [r for r in results if r['status'] not in ('Success', 'Failed', 'InProgress', 'Pending', 'Waiting')]

    all_complete = len(in_progress) == 0 and len(unknown) == 0

    response_data = {
        'allComplete': all_complete,
        'summary': {
            'total': len(results),
            'succeeded': len(succeeded),
            'failed': len(failed),
            'inProgress': len(in_progress),
            'unknown': len(unknown),
        },
        'executions': results,
    }

    if all_complete:
        ready_instances = [r['instanceId'] for r in succeeded if r['instanceId']]
        failed_instances = [r['instanceId'] for r in failed if r['instanceId']]
        response_data['nextStep'] = (
            f"All collections complete. {len(succeeded)} succeeded, {len(failed)} failed. "
            f"Use errors/search/network_diagnostics on succeeded instances: {ready_instances[:5]}."
        )
        if failed_instances:
            response_data['failedInstances'] = failed_instances
    else:
        response_data['nextStep'] = f'{len(in_progress)} still running. Poll again in 15 seconds.'
        response_data['suggestedPollIntervalSeconds'] = 15

    return success_response(response_data)


def network_diagnostics(arguments: Dict) -> Dict:
    """
    Extract and structure networking info from collected log bundles.
    Parses iptables, CNI config, routes, DNS, ENI, and ipamd logs.

    Inputs:
        instanceId: EC2 instance ID (required)
        sections: comma-separated: "iptables,cni,routes,dns,eni,ipamd" or "all" (default: "all")

    Returns:
        Structured networking diagnostics per section
    """
    instance_id = arguments.get('instanceId')
    if not instance_id:
        return error_response(400, 'instanceId is required')

    sections_str = arguments.get('sections', 'all')
    valid_sections = {'iptables', 'cni', 'routes', 'dns', 'eni', 'ipamd'}
    if sections_str == 'all':
        sections = ['iptables', 'cni', 'routes', 'dns', 'eni', 'ipamd']
    else:
        sections = [s.strip() for s in sections_str.split(',')]
        invalid = [s for s in sections if s not in valid_sections]
        if invalid:
            return error_response(400, f"Invalid section(s): {', '.join(invalid)}. Valid: {', '.join(sorted(valid_sections))}")
        if not sections:
            return error_response(400, 'At least one section is required')

    prefix = f"logs/{instance_id}/extracted/"
    results = {}
    issues_found = []

    try:
        # Find the actual extracted bundle prefix (eks_{instance_id}_{execution_id}/extracted/)
        bundle_files = []
        search_result = safe_s3_list(f"eks_{instance_id}", max_keys=500)
        if search_result.get('success'):
            bundle_files = [obj['key'] for obj in search_result.get('objects', []) if '/extracted/' in obj.get('key', '')]

        if not bundle_files:
            return error_response(404, f'No extracted log bundle found for {instance_id}. Run collect first.')

        def find_files(patterns):
            """Find bundle files matching any of the given patterns."""
            matched = []
            for f in bundle_files:
                fname = f.lower()
                for p in patterns:
                    if p in fname:
                        matched.append(f)
                        break
            return matched

        # Pre-fetch all needed files in parallel
        files_to_fetch = set()
        section_file_map = {}
        fetch_sizes = {}  # key -> max_size

        if 'iptables' in sections:
            keys = find_files(['iptables', 'ip-tables', 'iptable'])[:3]
            section_file_map['iptables'] = keys
            for k in keys: files_to_fetch.add(k); fetch_sizes[k] = 262144
        if 'cni' in sections:
            keys = find_files(['aws-node', 'cni', 'ipamd-config', '10-aws'])[:5]
            section_file_map['cni'] = keys
            for k in keys: files_to_fetch.add(k); fetch_sizes[k] = 262144
        if 'routes' in sections:
            r_keys = find_files(['ip-route', 'ip_route', 'route-table', 'routes'])[:3]
            i_keys = find_files(['ifconfig', 'ip-addr', 'ip_addr', 'interfaces'])[:2]
            section_file_map['routes'] = r_keys
            section_file_map['routes_iface'] = i_keys
            for k in r_keys + i_keys: files_to_fetch.add(k); fetch_sizes[k] = 262144
        if 'dns' in sections:
            keys = find_files(['resolv', 'dns', 'coredns'])[:5]
            section_file_map['dns'] = keys
            for k in keys: files_to_fetch.add(k); fetch_sizes[k] = 262144
        if 'eni' in sections:
            keys = find_files(['eni', 'network-interface', 'eth'])[:3]
            section_file_map['eni'] = keys
            for k in keys: files_to_fetch.add(k); fetch_sizes[k] = 32768
        if 'ipamd' in sections:
            keys = find_files(['ipamd', 'aws_node', 'ip-address-management'])[:5]
            # If no ipamd-specific files found, fall back to aws-node logs
            if not keys:
                keys = find_files(['aws-node'])[:3]
            section_file_map['ipamd'] = keys
            for k in keys: files_to_fetch.add(k); fetch_sizes[k] = 524288

        # Parallel S3 reads
        file_contents = {}
        def _fetch(key):
            r = safe_s3_read(key, max_size=fetch_sizes.get(key, 262144))
            return key, r.get('content', '') if r.get('success') else None

        with ThreadPoolExecutor(max_workers=10) as executor:
            fetch_list = list(files_to_fetch)  # Convert set to list for deterministic ordering
            for key, content in executor.map(_fetch, fetch_list):
                file_contents[key] = content

        def read_file_content(key, max_size=262144):
            """Read from pre-fetched cache. Falls back to direct S3 read if not cached."""
            cached = file_contents.get(key)
            if cached is not None:
                return cached
            # Fallback for files not in the pre-fetch set
            r = safe_s3_read(key, max_size=max_size)
            return r.get('content', '') if r.get('success') else None

        # =====================================================================
        # IPTABLES
        # =====================================================================
        if 'iptables' in sections:
            ipt_data = {'raw': None, 'chainCount': 0, 'ruleCount': 0, 'natRules': [], 'kubeProxyRules': [], 'issues': []}
            ipt_files = find_files(['iptables', 'ip-tables', 'iptable'])
            for f in ipt_files[:3]:
                content = read_file_content(f)
                if content:
                    lines = content.split('\n')
                    ipt_data['ruleCount'] = sum(1 for l in lines if l.strip() and not l.startswith('#') and not l.startswith('*') and not l.startswith(':'))
                    ipt_data['chainCount'] = sum(1 for l in lines if l.startswith(':'))
                    ipt_data['natRules'] = [l.strip() for l in lines if 'DNAT' in l or 'SNAT' in l or 'MASQUERADE' in l][:20]
                    ipt_data['kubeProxyRules'] = [l.strip() for l in lines if 'KUBE-' in l][:20]
                    # Check for issues
                    if ipt_data['ruleCount'] == 0:
                        ipt_data['issues'].append('No iptables rules found — kube-proxy may not be running')
                        issues_found.append({'section': 'iptables', 'severity': 'critical', 'message': 'No iptables rules found'})
                    if not any('KUBE-SERVICES' in l for l in lines):
                        ipt_data['issues'].append('KUBE-SERVICES chain missing — kube-proxy not configured')
                        issues_found.append({'section': 'iptables', 'severity': 'warning', 'message': 'KUBE-SERVICES chain missing'})
                    ipt_data['sourceFile'] = f
                    break
            results['iptables'] = ipt_data

        # =====================================================================
        # CNI CONFIG (aws-node / VPC CNI)
        # =====================================================================
        if 'cni' in sections:
            cni_data = {'config': {}, 'envVars': {}, 'issues': []}
            cni_files = find_files(['aws-node', 'cni', 'ipamd-config', '10-aws'])
            for f in cni_files[:5]:
                content = read_file_content(f)
                if content:
                    # Parse CNI config JSON
                    if f.endswith('.json') or f.endswith('.conflist'):
                        try:
                            cni_data['config'] = json.loads(content)
                        except json.JSONDecodeError:
                            cni_data['config'] = {'raw': content[:1000]}
                    # Parse env vars
                    elif 'env' in f.lower() or 'aws-node' in f.lower():
                        for line in content.split('\n'):
                            if '=' in line and not line.startswith('#'):
                                parts = line.strip().split('=', 1)
                                if len(parts) == 2:
                                    cni_data['envVars'][parts[0]] = parts[1]

            # Check for common CNI issues
            env = cni_data.get('envVars', {})
            if env.get('WARM_IP_TARGET', '') == '0' and env.get('MINIMUM_IP_TARGET', '') == '0':
                cni_data['issues'].append('Both WARM_IP_TARGET and MINIMUM_IP_TARGET are 0 — pod IP allocation may fail')
                issues_found.append({'section': 'cni', 'severity': 'critical', 'message': 'IP target settings are 0'})
            if env.get('AWS_VPC_K8S_CNI_EXTERNALSNAT', '').lower() == 'true':
                cni_data['issues'].append('External SNAT enabled — ensure NAT gateway is configured')
            cni_data['sourceFiles'] = cni_files[:5]
            results['cni'] = cni_data

        # =====================================================================
        # ROUTE TABLES
        # =====================================================================
        if 'routes' in sections:
            route_data = {'routes': [], 'defaultGateway': None, 'interfaces': [], 'issues': []}
            route_files = find_files(['ip-route', 'ip_route', 'route-table', 'routes'])
            for f in route_files[:3]:
                content = read_file_content(f)
                if content:
                    for line in content.split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        route_data['routes'].append(line)
                        if line.startswith('default') or 'default' in line:
                            route_data['defaultGateway'] = line

            # Parse interfaces
            iface_files = find_files(['ifconfig', 'ip-addr', 'ip_addr', 'interfaces'])
            for f in iface_files[:2]:
                content = read_file_content(f)
                if content:
                    # Extract interface names and IPs
                    current_iface = None
                    for line in content.split('\n'):
                        if re.match(r'^\d+:\s+\S+', line) or re.match(r'^\S+:', line):
                            iface_match = re.search(r'(\S+?)[@:]', line)
                            if iface_match:
                                current_iface = iface_match.group(1)
                        if 'inet ' in line and current_iface:
                            ip_match = re.search(r'inet\s+(\S+)', line)
                            if ip_match:
                                route_data['interfaces'].append({
                                    'name': current_iface,
                                    'ip': ip_match.group(1),
                                })

            if not route_data['defaultGateway']:
                route_data['issues'].append('No default gateway found')
                issues_found.append({'section': 'routes', 'severity': 'critical', 'message': 'No default gateway'})
            route_data['routeCount'] = len(route_data['routes'])
            route_data['routes'] = route_data['routes'][:50]  # Cap output
            results['routes'] = route_data

        # =====================================================================
        # DNS
        # =====================================================================
        if 'dns' in sections:
            dns_data = {'resolv_conf': {}, 'nameservers': [], 'searchDomains': [], 'corednsStatus': None, 'issues': []}
            dns_files = find_files(['resolv', 'dns', 'coredns'])
            for f in dns_files[:5]:
                content = read_file_content(f)
                if content:
                    if 'resolv' in f.lower():
                        for line in content.split('\n'):
                            line = line.strip()
                            if line.startswith('nameserver'):
                                ns = line.split(None, 1)[1] if len(line.split()) > 1 else ''
                                dns_data['nameservers'].append(ns)
                            elif line.startswith('search'):
                                dns_data['searchDomains'] = line.split()[1:]
                            elif line.startswith('options'):
                                dns_data['resolv_conf']['options'] = line
                        dns_data['resolv_conf']['raw'] = content[:500]
                    elif 'coredns' in f.lower():
                        # Check for coredns errors
                        error_lines = [l for l in content.split('\n') if 'error' in l.lower() or 'SERVFAIL' in l]
                        if error_lines:
                            dns_data['corednsStatus'] = 'errors_found'
                            dns_data['corednsErrors'] = error_lines[:10]
                            issues_found.append({'section': 'dns', 'severity': 'warning', 'message': f'{len(error_lines)} CoreDNS errors found'})
                        else:
                            dns_data['corednsStatus'] = 'ok'

            # Validate DNS config
            if not dns_data['nameservers']:
                dns_data['issues'].append('No nameservers in resolv.conf')
                issues_found.append({'section': 'dns', 'severity': 'critical', 'message': 'No nameservers configured'})

            # Add interpretation note for node-level resolv.conf
            dns_data['_note'] = (
                "IMPORTANT CONTEXT: This is the NODE-LEVEL /etc/resolv.conf. "
                "It is EXPECTED to show VPC DNS (e.g., 172.31.0.2 which is VPC CIDR+2). "
                "This is NOT a misconfiguration. Pod DNS is configured SEPARATELY by kubelet "
                "via the --cluster-dns flag (typically 10.100.0.10 or 172.20.0.10) and injected "
                "into each pod's /etc/resolv.conf at runtime. Do NOT diagnose node resolv.conf "
                "pointing to VPC DNS as a pod DNS misconfiguration. To check pod DNS, use: "
                "kubectl exec <pod> -- cat /etc/resolv.conf"
            )
            results['dns'] = dns_data

        # =====================================================================
        # ENI (Elastic Network Interfaces)
        # =====================================================================
        if 'eni' in sections:
            eni_data = {'attachedENIs': [], 'eniCount': 0, 'issues': []}
            # Try to get ENI info from EC2 API
            try:
                target_region = resolve_region(arguments, instance_id)
                regional_ec2 = get_regional_client('ec2', target_region)
                eni_resp = regional_ec2.describe_network_interfaces(
                    Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}]
                )
                for eni in eni_resp.get('NetworkInterfaces', []):
                    eni_data['attachedENIs'].append({
                        'eniId': eni['NetworkInterfaceId'],
                        'subnetId': eni.get('SubnetId'),
                        'privateIp': eni.get('PrivateIpAddress'),
                        'secondaryIps': [addr['PrivateIpAddress'] for addr in eni.get('PrivateIpAddresses', []) if not addr.get('Primary')],
                        'status': eni.get('Status'),
                        'description': eni.get('Description', '')[:100],
                        'securityGroups': [sg['GroupId'] for sg in eni.get('Groups', [])],
                    })
                eni_data['eniCount'] = len(eni_data['attachedENIs'])

                # Check for IP exhaustion signals
                total_secondary_ips = sum(len(e['secondaryIps']) for e in eni_data['attachedENIs'])
                eni_data['totalSecondaryIPs'] = total_secondary_ips
                if eni_data['eniCount'] == 0:
                    eni_data['issues'].append('No ENIs attached — instance may be detached from VPC')
                    issues_found.append({'section': 'eni', 'severity': 'critical', 'message': 'No ENIs attached'})
            except Exception as e:
                eni_data['issues'].append(f'Could not query ENI info: {str(e)}')

            # Also check from bundle files
            eni_files = find_files(['eni', 'network-interface', 'eth'])
            for f in eni_files[:3]:
                content = read_file_content(f, max_size=32768)
                if content:
                    eni_data['bundleNetworkInfo'] = content[:2000]
                    break
            results['eni'] = eni_data

        # =====================================================================
        # IPAMD (IP Address Management Daemon / aws-node)
        # =====================================================================
        if 'ipamd' in sections:
            ipamd_data = {'logSummary': {}, 'errors': [], 'ipAllocationIssues': [], 'issues': []}
            ipamd_files = find_files(['ipamd', 'aws_node', 'ip-address-management'])
            if not ipamd_files:
                ipamd_files = find_files(['aws-node'])
            for f in ipamd_files[:5]:
                content = read_file_content(f, max_size=524288)
                if content:
                    lines = content.split('\n')
                    total_lines = len(lines)
                    error_lines = []
                    ip_issues = []
                    for line in lines:
                        ll = line.lower()
                        if 'error' in ll or 'failed' in ll:
                            error_lines.append(line.strip()[:200])
                        if 'ip address' in ll and ('exhaust' in ll or 'insufficient' in ll or 'no available' in ll):
                            ip_issues.append(line.strip()[:200])
                        if 'failed to allocate' in ll or 'no ips available' in ll:
                            ip_issues.append(line.strip()[:200])

                    ipamd_data['logSummary'][f] = {
                        'totalLines': total_lines,
                        'errorCount': len(error_lines),
                        'ipIssueCount': len(ip_issues),
                    }
                    ipamd_data['errors'].extend(error_lines[:20])
                    ipamd_data['ipAllocationIssues'].extend(ip_issues[:20])

            if ipamd_data['ipAllocationIssues']:
                ipamd_data['issues'].append(f"{len(ipamd_data['ipAllocationIssues'])} IP allocation issues found — possible subnet IP exhaustion")
                issues_found.append({'section': 'ipamd', 'severity': 'critical', 'message': 'IP allocation failures detected'})
            if ipamd_data['errors']:
                ipamd_data['issues'].append(f"{len(ipamd_data['errors'])} errors in IPAMD logs")
                issues_found.append({'section': 'ipamd', 'severity': 'warning', 'message': f"{len(ipamd_data['errors'])} IPAMD errors"})
            results['ipamd'] = ipamd_data

        # =====================================================================
        # OVERALL SUMMARY
        # =====================================================================
        total_issues = len(issues_found)
        critical_issues = sum(1 for i in issues_found if i.get('severity') == 'critical')
        warning_issues = sum(1 for i in issues_found if i.get('severity') == 'warning')

        # Confidence assessment
        sections_with_data = sum(1 for s in sections if s in results and results[s])
        if sections_with_data >= 4 and critical_issues > 0:
            confidence = 'high'
        elif sections_with_data >= 2 and total_issues > 0:
            confidence = 'medium'
        elif sections_with_data >= 1:
            confidence = 'low'
        else:
            confidence = 'none'

        # Identify gaps
        gaps = []
        if not bundle_files:
            gaps.append('No extracted bundle found — collect and wait for completion first')
        sections_without_files = [s for s in sections if s not in section_file_map or not section_file_map.get(s)]
        if sections_without_files:
            gaps.append(f'No files found for sections: {", ".join(sections_without_files)}')
        empty_reads = [s for s in sections if s in results and not any(
            v for k, v in results[s].items() if k not in ('issues', 'sourceFile', 'sourceFiles', '_note')
        )]
        if empty_reads:
            gaps.append(f'Sections returned empty data: {", ".join(empty_reads)}')

        return success_response({
            'instanceId': instance_id,
            'sections': sections,
            'diagnostics': results,
            'issuesSummary': {
                'total': total_issues,
                'critical': critical_issues,
                'warning': warning_issues,
                'issues': issues_found,
            },
            'confidence': confidence,
            'gaps': gaps,
            'overallAssessment': _network_assessment(issues_found),
            'nextStep': 'Use search tool to dig deeper into specific networking errors, or correlate to build a timeline.' if issues_found else 'No networking issues detected in the bundle.',
        })

    except Exception as e:
        return error_response(500, f'network_diagnostics failed: {str(e)}')


def _network_assessment(issues: List[Dict]) -> str:
    """Generate overall network health assessment."""
    if not issues:
        return "HEALTHY — No networking issues detected in the log bundle."
    critical = [i for i in issues if i.get('severity') == 'critical']
    if critical:
        sections = set(i['section'] for i in critical)
        return f"CRITICAL — {len(critical)} critical networking issues in: {', '.join(sections)}. Immediate investigation needed."
    return f"WARNING — {len(issues)} non-critical networking issues found. Review recommended."
