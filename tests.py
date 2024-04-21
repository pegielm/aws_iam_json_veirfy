import unittest
from verify_iam_rp_json import verify_json, ver_simple
'''
Tests for verify_iam_rp_json.py
'''
class test_iam_role_policy_json(unittest.TestCase):   
    def test_invalid_policy_name(self):
        json_data = { "!!!wrong!!!": "root", "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "*" } ] } }
        self.assertTrue(verify_json(json_data))

    def test_missing_policy_name(self):
        json_data = { "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "*" } ] } }
        self.assertTrue(verify_json(json_data))

    def test_invalid_version(self):
        json_data = { "PolicyName": "root", "PolicyDocument": { "Version": "!!!wrong version!!!", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "*" } ] } }
        self.assertTrue(verify_json(json_data))
    
    def test_invalid_effect(self):
        json_data = { "PolicyName": "root", "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "!!!wrong effect!!!", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "*" } ] } }
        self.assertTrue(verify_json(json_data))

    def test_missing_action_or_notaction(self):
        json_data = { "PolicyName": "root", "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Resource": "*" } ] } }
        self.assertTrue(verify_json(json_data))

    def test_resource_is_star(self):
        json_data = { "PolicyName": "root", "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "*" } ] } }
        self.assertFalse(verify_json(json_data))
    
    def test_resource_is_not_star(self):
        json_data = { "PolicyName": "root", "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "!!!not star!!!" } ] } }
        self.assertTrue(verify_json(json_data))
    
    def test_multiple_statements(self):
        json_data = { "PolicyName": "root", "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "!!!not star!!!" }, { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "*" } ] } }
        self.assertFalse(verify_json(json_data))

    def test_ver_simple(self):
        json_data = { "PolicyName": "root", "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ], "Resource": "*" } ] } }
        self.assertFalse(ver_simple(json_data))

    def test_ver_simple_no_resource(self):
        json_data = { "PolicyName": "root", "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Sid": "IamListAccess", "Effect": "Allow", "Action": [ "iam:ListRoles", "iam:ListUsers" ] } ] } }
        self.assertTrue(ver_simple(json_data))
    
if __name__ == "__main__":
    unittest.main()
