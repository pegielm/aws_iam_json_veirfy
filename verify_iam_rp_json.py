import json
import argparse as ap
import re 
'''
program that verifies the json file format of an IAM Role Policy

fuction verify_json(file_path) -> bool 
    is more complex and checks validation of the json format of the IAM Role Policy and if the Resource field contains a value of "*"
    also returns varius exceptions for debugging purposes, in this case its print() but it can be changed to logging or other methods

function ver_simple(path) -> bool
    is a simpler version of the function that checks if the json file contains a resource field with a value of "*"
'''
def ver_simple(path)->bool:
    '''
    Simplified version
    Returns True if the json file contains a resource field with a value of "*" otherwise returns False

    Parameters
    ----------
    path : str
        path to the json file

    Returns
    -------
    bool
        True if the json file contains a resource field with a value of "*" otherwise False
    '''
    try:
        with open(path,"r") as f:
            iam_rp = json.load(f)
        for statement in iam_rp["PolicyDocument"]["Statement"]:
            if statement["Resource"] == "*":
                return False
    except Exception:
        pass
    return True

def verify_json(file_path)->bool:
    '''
    Retruns True if the json file is valid IAM Role Policy and the Resource field contains a value of "*" otherwise returns False

    Parameters 
    ----------
    file_path : str
        path to the json file

    Returns
    -------
    bool
        True if  Resource field contains a value of "*" and json file is valid IAM Role Policy ,otherwise False
    '''
    try:
        with open(file_path,"r") as f:
            iam_role_policy = json.load(f)

        if  "PolicyName" not in iam_role_policy and "PolicyDocument" not in iam_role_policy:
             raise Exception("One of IAM Role Policy fields is missing")
        if re.match(r"[\w+=,.@-]+", iam_role_policy["PolicyName"]) is None:
            raise Exception("Invalid PolicyName")
        #IAM supports the following Version element values: 2012-10-17 , 2008-10-17 https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
        if iam_role_policy["PolicyDocument"]["Version"] != "2012-10-17" or iam_role_policy["PolicyDocument"]["Version"] == "2008-10-17": 
            raise Exception("Invalid Version")

        for statement in iam_role_policy["PolicyDocument"]["Statement"]: 
            #Valid values for Effect are Allow and Deny. The Effect value is case sensitive. https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_effect.html
            if statement["Effect"] not in ["Allow", "Deny"]:
                raise Exception("Invalid Effect in Statement") 
            #Statements must include either an Action or NotAction element. https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html
            if "Action" not in statement and "NotAction" not in statement: 
                raise Exception("Action or NotAction field is missing")
            
            if statement["Resource"] == "*":
                return False
    except json.JSONDecodeError:
        print("Invalid file format, not a json file") # can be changed to logging 
    except FileNotFoundError:
        print("File not found") # can be changed to logging 
    except KeyError:
        print("One of fields doesn't exist") # can be changed to logging 
    except Exception as e:
        print(e) # can be changed to logging 
    
    return True


if __name__=="__main__":
    ap = ap.ArgumentParser()
    ap.add_argument("-f", "--file", required=True, help="path to json file")
    args = vars(ap.parse_args())
    print(verify_json(args["file"]))
    print(ver_simple(args["file"]))
    