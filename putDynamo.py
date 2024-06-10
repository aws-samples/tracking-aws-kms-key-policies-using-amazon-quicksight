import argparse
import json

import boto3

# Arguments
parser = argparse.ArgumentParser("Read JSON File to load into DynamoDB")
parser.add_argument("-f", "--file", help="JSON file", required=True)
parser.add_argument("-t", "--tablename", help="Table name", required=True)
parser.add_argument("-r", "--region", help="Region", required=True)


# Parse the arguments
args = vars(parser.parse_args())

# Use the arguments
filename = args["file"]
tablename = args["tablename"]
region = args["region"]

dynamodbclient = boto3.resource("dynamodb", region_name=region)
sample_table = dynamodbclient.Table(tablename)

with open(filename, "r") as myfile:
    data = myfile.read()

# parse file
obj = json.loads(data)

print(f"Obj: {obj}")
for item in obj:
    print(f"item:  {item}")
    for key in item.keys():
        print(f"key: {key}")
        print(f"value: {item[key]}")
    response = sample_table.put_item(Item=item)
