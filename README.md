# aws_iam_json_veirfy

## Description

This script is used to verify the IAM role policy json file. 
In code there are two functions:

- one just checks if one of the Resource fields is "*" (simple_ver())
- second also checks if json file have correct format for aws iam role policy. (verify_json())

## How to run
```
python3 verify_iam_rp_json.py [-h] -f <file_path>
```

## Testing
```
python3 tests.py
```