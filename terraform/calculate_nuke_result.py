import json
import boto3

def lambda_handler(event, context):
    print(event)
    client = boto3.client('account')
    account_client = client.list_regions(RegionOptStatusContains=['DISABLED'])
    disabled_regions = []
    for reg in account_client['Regions']:
        disabled_regions.append(reg['RegionName'])
    print(disabled_regions)
    account_id = context.invoked_function_arn.split(":")[4]
    results_list = event["NukeFinalMapAllRegionsOutput"]["filteredResult"]
    for result in results_list:
        if result["Status"] != "Succeeded" and result["Region"] not in disabled_regions:
            return {
            'NukeFinal': {
                "Status" : "Failed"
            },
            "NukeFinalMapAllRegionsOutput": event["NukeFinalMapAllRegionsOutput"]
        }
    
    return {
        'NukeFinal': {
            "Status" : "Succeeded"
        },
        "NukeFinalMapAllRegionsOutput": event["NukeFinalMapAllRegionsOutput"]
    }