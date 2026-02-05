import json
import boto3
import os
from datetime import datetime

ssm_client = boto3.client('ssm')
s3_client = boto3.client('s3')
LOGS_BUCKET = os.environ['LOGS_BUCKET_NAME']

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    delimiter = "___"
    original_tool_name = context.client_context.custom['bedrockAgentCoreToolName']
    tool_name = original_tool_name[original_tool_name.index(delimiter) + len(delimiter):]
    print(f"Extracted tool name: {tool_name}")
    
    if tool_name == 'run_eks_log_collection':
        return run_eks_log_collection(event)
    elif tool_name == 'get_automation_status':
        return get_automation_status(event)
    elif tool_name == 'list_automations':
        return list_automations(event)
    elif tool_name == 'list_collected_logs':
        return list_collected_logs(event)
    elif tool_name == 'get_log_content':
        return get_log_content(event)
    else:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': f'Unknown tool: {tool_name}',
                'available_tools': ['run_eks_log_collection', 'get_automation_status', 
                                   'list_automations', 'list_collected_logs', 'get_log_content']
            })
        }

def run_eks_log_collection(arguments):
    instance_id = arguments.get('instanceId')
    if not instance_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'instanceId is required'})}
    try:
        params = {
            'EKSInstanceId': [instance_id],
            'LogDestination': [LOGS_BUCKET],
            'AutomationAssumeRole': [os.environ.get('SSM_AUTOMATION_ROLE_ARN', '')]
        }
        response = ssm_client.start_automation_execution(
            DocumentName='AWSSupport-CollectEKSInstanceLogs',
            Parameters=params
        )
        execution_id = response['AutomationExecutionId']
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'message': 'EKS log collection started',
                'executionId': execution_id,
                'instanceId': instance_id,
                's3Bucket': LOGS_BUCKET,
                'checkStatusWith': f'Use get_automation_status with executionId: {execution_id}'
            })
        }
    except ssm_client.exceptions.AutomationDefinitionNotFoundException:
        return {
            'statusCode': 404,
            'body': json.dumps({
                'error': 'AWSSupport-CollectEKSInstanceLogs document not found',
                'suggestion': 'This document may not be available in your region or account'
            })
        }
    except Exception as e:
        print(f"Error starting automation: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps({'error': f'Failed to start EKS log collection: {str(e)}'})}

def get_automation_status(arguments):
    execution_id = arguments.get('executionId')
    if not execution_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'executionId is required'})}
    try:
        response = ssm_client.get_automation_execution(AutomationExecutionId=execution_id)
        execution = response['AutomationExecution']
        result = {
            'executionId': execution_id,
            'status': execution['AutomationExecutionStatus'],
            'documentName': execution.get('DocumentName', ''),
            'startTime': execution.get('ExecutionStartTime', '').isoformat() if execution.get('ExecutionStartTime') else None,
            'endTime': execution.get('ExecutionEndTime', '').isoformat() if execution.get('ExecutionEndTime') else None,
        }
        if 'Outputs' in execution:
            result['outputs'] = execution['Outputs']
        if execution['AutomationExecutionStatus'] == 'Failed':
            result['failureMessage'] = execution.get('FailureMessage', 'Unknown failure')
        if 'Parameters' in execution:
            params = execution['Parameters']
            if 'S3BucketName' in params and 'S3Path' in params:
                result['s3Location'] = f"s3://{params['S3BucketName'][0]}/{params['S3Path'][0]}"
        return {'statusCode': 200, 'body': json.dumps({'success': True, 'automation': result})}
    except ssm_client.exceptions.AutomationExecutionNotFoundException:
        return {'statusCode': 404, 'body': json.dumps({'error': f'Automation execution {execution_id} not found'})}
    except Exception as e:
        print(f"Error getting automation status: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps({'error': f'Failed to get automation status: {str(e)}'})}

def list_automations(arguments):
    max_results = arguments.get('maxResults', 10)
    document_name = arguments.get('documentName', 'AWSSupport-CollectEKSInstanceLogs')
    try:
        filters = []
        if document_name:
            filters.append({'Key': 'DocumentNamePrefix', 'Values': [document_name]})
        response = ssm_client.describe_automation_executions(Filters=filters, MaxResults=min(max_results, 50))
        executions = []
        for exec in response.get('AutomationExecutionMetadataList', []):
            executions.append({
                'executionId': exec['AutomationExecutionId'],
                'documentName': exec.get('DocumentName', ''),
                'status': exec['AutomationExecutionStatus'],
                'startTime': exec.get('ExecutionStartTime', '').isoformat() if exec.get('ExecutionStartTime') else None,
                'endTime': exec.get('ExecutionEndTime', '').isoformat() if exec.get('ExecutionEndTime') else None,
            })
        return {'statusCode': 200, 'body': json.dumps({'success': True, 'executions': executions, 'count': len(executions)})}
    except Exception as e:
        print(f"Error listing automations: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps({'error': f'Failed to list automations: {str(e)}'})}

def list_collected_logs(arguments):
    instance_id = arguments.get('instanceId', '')
    try:
        prefix = 'eks-logs/'
        if instance_id:
            prefix = f'eks-logs/{instance_id}/'
        response = s3_client.list_objects_v2(Bucket=LOGS_BUCKET, Prefix=prefix, MaxKeys=100)
        logs = []
        if 'Contents' in response:
            for obj in response['Contents']:
                logs.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'lastModified': obj['LastModified'].isoformat()
                })
        return {'statusCode': 200, 'body': json.dumps({'success': True, 'logs': logs, 'count': len(logs), 'bucket': LOGS_BUCKET, 'prefix': prefix})}
    except Exception as e:
        print(f"Error listing logs: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps({'error': f'Failed to list collected logs: {str(e)}'})}

def get_log_content(arguments):
    log_key = arguments.get('logKey')
    max_bytes = arguments.get('maxBytes', 100000)
    if not log_key:
        return {'statusCode': 400, 'body': json.dumps({'error': 'logKey is required'})}
    try:
        head_response = s3_client.head_object(Bucket=LOGS_BUCKET, Key=log_key)
        file_size = head_response['ContentLength']
        if file_size > max_bytes:
            range_header = f'bytes=0-{max_bytes-1}'
            response = s3_client.get_object(Bucket=LOGS_BUCKET, Key=log_key, Range=range_header)
            truncated = True
        else:
            response = s3_client.get_object(Bucket=LOGS_BUCKET, Key=log_key)
            truncated = False
        content = response['Body'].read()
        try:
            content_str = content.decode('utf-8')
        except UnicodeDecodeError:
            content_str = content.decode('latin-1')
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'logKey': log_key,
                'content': content_str,
                'size': file_size,
                'truncated': truncated,
                'truncatedAt': max_bytes if truncated else None
            })
        }
    except s3_client.exceptions.NoSuchKey:
        return {'statusCode': 404, 'body': json.dumps({'error': f'Log file not found: {log_key}', 'suggestion': 'Use list_collected_logs to see available log files'})}
    except Exception as e:
        print(f"Error getting log content: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps({'error': f'Failed to get log content: {str(e)}'})}
