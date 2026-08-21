def explain(f):
    text=(f.get('title','')+' '+f.get('description','')+' '+f.get('recommendation','')).lower()
    sev=f.get('severity','UNKNOWN').upper()
    if 's3' in text and 'public' in text:
        impact='The S3 bucket may expose data to unintended internet users.'
        fix='Enable S3 Block Public Access and verify bucket policy and ACLs.'
    elif 'security group' in text or '0.0.0.0/0' in text:
        impact='A network rule may expose a service to the public internet.'
        fix='Restrict ingress to the smallest trusted CIDR and remove unused rules.'
    elif 'ebs' in text or 'unattached' in text:
        impact='An unattached EBS volume can continue generating storage charges.'
        fix='Confirm it is unused, create a snapshot, then delete the volume.'
    else:
        impact='The finding indicates a configuration that may increase security or operating risk.'
        fix=f.get('recommendation') or 'Review and apply the least-privileged remediation.'
    return {'summary':f.get('title'),'severity':sev,
            'priority_score':{'CRITICAL':100,'HIGH':80,'MEDIUM':50,'LOW':20}.get(sev,10),
            'business_impact':impact,'recommended_fix':fix}

def savings(resource):
    d=resource.get('data',{}) or {}
    if resource.get('resource_type')=='EBS' and not d.get('attached'):
        return {'monthly_savings':round(float(d.get('size_gb') or 0)*0.08,2),
                'basis':'Illustrative $0.08/GB-month estimate; verify region/type.'}
    if resource.get('resource_type')=='EC2' and d.get('state')=='stopped':
        return {'monthly_savings':5.0,'basis':'Illustrative estimate; verify actual storage/compute cost.'}
    return {'monthly_savings':0,'basis':'No deterministic estimate.'}
