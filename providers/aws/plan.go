package aws

import (
	"encoding/json"
	"fmt"
	"regexp"
)

type CloudFormationPlan struct {
	ControlIDs []string        `json:"controlIds"`
	Risk       string          `json:"risk"`
	CostImpact string          `json:"costImpact"`
	Template   json.RawMessage `json:"template"`
}

var trailNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{3,128}$`)

func GenerateCloudFormationPlan(trailName string) (CloudFormationPlan, error) {
	if !trailNamePattern.MatchString(trailName) {
		return CloudFormationPlan{}, fmt.Errorf("trail name must be 3-128 safe CloudTrail characters")
	}
	template := map[string]any{
		"AWSTemplateFormatVersion": "2010-09-09",
		"Description":              "Reviewable TriSOC Attestor organization CloudTrail remediation. Controls: aws.cloudtrail.organization_multi_region, aws.cloudtrail.log_file_validation. Retained resources require deliberate rollback cleanup.",
		"Parameters": map[string]any{
			"TrailName":      map[string]any{"Type": "String", "Default": trailName, "AllowedPattern": "^[A-Za-z0-9._-]{3,128}$"},
			"OrganizationId": map[string]any{"Type": "String", "Description": "AWS Organizations ID used in the CloudTrail delivery prefix", "AllowedPattern": "^o-[a-z0-9]{10,32}$"},
			"KMSKeyArn":      map[string]any{"Type": "String", "Description": "Existing customer-managed KMS key ARN whose policy permits CloudTrail encryption"},
		},
		"Resources": map[string]any{
			"LogBucket": map[string]any{
				"Type":                "AWS::S3::Bucket",
				"DeletionPolicy":      "Retain",
				"UpdateReplacePolicy": "Retain",
				"Properties": map[string]any{
					"BucketEncryption":               map[string]any{"ServerSideEncryptionConfiguration": []any{map[string]any{"ServerSideEncryptionByDefault": map[string]any{"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": map[string]any{"Ref": "KMSKeyArn"}}}}},
					"PublicAccessBlockConfiguration": map[string]any{"BlockPublicAcls": true, "BlockPublicPolicy": true, "IgnorePublicAcls": true, "RestrictPublicBuckets": true},
					"VersioningConfiguration":        map[string]any{"Status": "Enabled"},
				},
			},
			"LogBucketPolicy": map[string]any{
				"Type": "AWS::S3::BucketPolicy",
				"Properties": map[string]any{
					"Bucket": map[string]any{"Ref": "LogBucket"},
					"PolicyDocument": map[string]any{
						"Version": "2012-10-17",
						"Statement": []any{
							map[string]any{"Sid": "CloudTrailAclCheck", "Effect": "Allow", "Principal": map[string]any{"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": map[string]any{"Fn::GetAtt": []string{"LogBucket", "Arn"}}, "Condition": map[string]any{"StringEquals": map[string]any{"aws:SourceArn": map[string]any{"Fn::Sub": "arn:${AWS::Partition}:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/${TrailName}"}}}},
							map[string]any{"Sid": "CloudTrailOrganizationWrite", "Effect": "Allow", "Principal": map[string]any{"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject", "Resource": map[string]any{"Fn::Sub": "${LogBucket.Arn}/AWSLogs/${OrganizationId}/*"}, "Condition": map[string]any{"StringEquals": map[string]any{"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": map[string]any{"Fn::Sub": "arn:${AWS::Partition}:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/${TrailName}"}}}},
						},
					},
				},
			},
			"OrganizationTrail": map[string]any{
				"Type":      "AWS::CloudTrail::Trail",
				"DependsOn": "LogBucketPolicy",
				"Properties": map[string]any{
					"TrailName":                  map[string]any{"Ref": "TrailName"},
					"S3BucketName":               map[string]any{"Ref": "LogBucket"},
					"KMSKeyId":                   map[string]any{"Ref": "KMSKeyArn"},
					"IsLogging":                  true,
					"IsOrganizationTrail":        true,
					"IsMultiRegionTrail":         true,
					"IncludeGlobalServiceEvents": true,
					"EnableLogFileValidation":    true,
					"EventSelectors":             []any{map[string]any{"IncludeManagementEvents": true, "ReadWriteType": "All"}},
				},
			},
		},
	}
	raw, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return CloudFormationPlan{}, err
	}
	return CloudFormationPlan{ControlIDs: []string{"aws.cloudtrail.organization_multi_region", "aws.cloudtrail.log_file_validation"}, Risk: "high", CostImpact: "usage_dependent", Template: raw}, nil
}
