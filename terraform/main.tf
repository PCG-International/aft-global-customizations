terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}


resource "aws_iam_policy" "NukeAccountCleanserPolicy" {
  name        = "NukeAccountCleanser"
  path        = var.IAMPath
  description = "Managed policy for nuke account cleaning"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
        Sid      = "WhitelistedServices"
      },
    ]
  })
}

resource "aws_iam_role" "NukeAccountCleanserRole" {
  name                 = var.NukeCleanserRoleName
  description          = "Nuke Auto account cleanser role for Dev/Sandbox accounts"
  max_session_duration = 7200
  tags = {
    "privileged"  = "true"
    "description" = "PrivilegedReadWrite:auto-account-cleanser-role"
    "owner"       = var.Owner
  }

  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Effect" : "Allow",
      "Action" : "sts:AssumeRole",
      "Principal" : {
        "AWS" : [aws_iam_role.NukeCodeBuildProjectRole.arn]
      }
    }]
  })

  managed_policy_arns = [aws_iam_policy.NukeAccountCleanserPolicy.arn]

  path = var.IAMPath
}


resource "aws_iam_role" "NukeCodeBuildProjectRole" {
  name = "NukeCodeBuildProject-${var.stack_name}"

  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Principal" : {
            "Service" : "codebuild.amazonaws.com"
          },
          "Action" : "sts:AssumeRole"
        }
      ]
    }
  )
}

resource "aws_iam_policy" "NukeCodeBuildLogsPolicy" {
  name        = "NukeCodeBuildLogsPolicy"
  description = "Policy for NukeCodeBuildLogs"

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogStreams",
            "logs:FilterLogEvents"
          ],
          "Resource" : [
            "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:AccountNuker-${var.stack_name}",
            "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:AccountNuker-${var.stack_name}:*"
          ]
        }
      ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "NukeCodeBuildLogsPolicyAttachment" {
  role       = aws_iam_role.NukeCodeBuildProjectRole.name
  policy_arn = aws_iam_policy.NukeCodeBuildLogsPolicy.arn
}

resource "aws_iam_policy" "AssumeNukePolicy" {
  name        = "AssumeNukePolicy"
  description = "Policy for AssumeNuke"

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : "sts:AssumeRole",
          "Resource" : "arn:aws:iam::*:role/${var.NukeCleanserRoleName}"
        }
      ]
    }
  )
}

resource "aws_iam_policy" "NukeListOUAccounts" {
  name        = "NukeListOUAccounts"
  description = "Policy for NukeListOUAccounts"

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : "organizations:ListAccountsForParent",
          "Resource" : "*"
        }
      ]
    }
  )
}

resource "aws_iam_policy" "S3BucketReadOnly" {
  name        = "S3BucketReadOnly"
  description = "Policy for S3BucketReadOnly"

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "s3:Get*",
            "s3:List*"
          ],
          "Resource" : [
            "arn:aws:s3:::${aws_s3_bucket.NukeS3Bucket.id}",
            "arn:aws:s3:::${aws_s3_bucket.NukeS3Bucket.id}/*"
          ]
        }
      ]
    }
  )
}

resource "aws_iam_policy" "SNSPublishPolicy" {
  name        = "SNSPublishPolicy"
  description = "Policy for SNSPublishPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sns:ListTagsForResource",
        "sns:ListSubscriptionsByTopic",
        "sns:GetTopicAttributes",
        "sns:Publish"
      ]
      Resource = [
        aws_sns_topic.NukeEmailTopic.arn
      ]
    }]
  })
}

resource "aws_codebuild_project" "NukeCodeBuildProject" {
  name          = "AccountNuker-${var.stack_name}"
  description   = "Builds a container to run AWS-Nuke for all accounts within the specified account/regions"
  service_role  = aws_iam_role.NukeCodeBuildProjectRole.arn
  badge_enabled = false
  build_timeout = 120

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                       = "aws/codebuild/docker:18.09.0"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = true
    type                        = "LINUX_CONTAINER"

    environment_variable {
      name  = "AWS_NukeDryRun"
      type  = "PLAINTEXT"
      value = var.AWSNukeDryRunFlag
    }

    environment_variable {
      name  = "AWS_NukeVersion"
      type  = "PLAINTEXT"
      value = var.AWSNukeVersion
    }

    environment_variable {
      name  = "Publish_TopicArn"
      type  = "PLAINTEXT"
      value = aws_sns_topic.NukeEmailTopic.arn
    }

    environment_variable {
      name  = "NukeS3Bucket"
      type  = "PLAINTEXT"
      value = aws_s3_bucket.NukeS3Bucket.id
    }

    environment_variable {
      name  = "NukeAssumeRoleArn"
      type  = "PLAINTEXT"
      value = aws_iam_role.NukeAccountCleanserRole.arn
    }

    environment_variable {
      name  = "NukeCodeBuildProjectName"
      type  = "PLAINTEXT"
      value = "AccountNuker-${var.stack_name}"
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name = "AccountNuker-${var.stack_name}"
      status     = "ENABLED"
    }
  }

  source {
    buildspec = file("build_spec.yaml")
    type      = "NO_SOURCE"
  }

}

resource "aws_iam_account_alias" "alias" {
  account_alias = join("-", [
    data.aws_caller_identity.current.account_id,
    data.aws_region.current.name
  ])
}

resource "aws_s3_bucket" "NukeS3Bucket" {
  bucket = join("-", [
    var.BucketName,
    data.aws_caller_identity.current.account_id,
    data.aws_region.current.name
  ])

  lifecycle {
    prevent_destroy = false
  }

  tags = {
    "DoNotNuke" = "True"
    "owner"     = var.Owner
  }
}

output "NukeS3Bucket" {
  value = aws_s3_bucket.NukeS3Bucket.id
}


resource "aws_s3_object" "pyconfigfile" {
  bucket = aws_s3_bucket.NukeS3Bucket.id
  key    = "nuke_config_update.py"
  source = "nuke_config_update.py"

  # The filemd5() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the md5() function and the file() function:
  # etag = "${md5(file("path/to/file"))}"
  etag = filemd5("nuke_config_update.py")
}

resource "aws_s3_object" "yamlconfigfile" {
  bucket = aws_s3_bucket.NukeS3Bucket.id
  key    = "nuke_generic_config.yaml"
  source = "nuke_generic_config.yaml"

  # The filemd5() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the md5() function and the file() function:
  # etag = "${md5(file("path/to/file"))}"
  etag = filemd5("nuke_generic_config.yaml")
}

resource "aws_s3_bucket_public_access_block" "public_Access" {
  bucket                  = aws_s3_bucket.NukeS3Bucket.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "NukeS3BucketPolicy" {
  bucket = aws_s3_bucket.NukeS3Bucket.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "ForceSSLOnlyAccess",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : "s3:*",
        "Resource" : [
          "${aws_s3_bucket.NukeS3Bucket.arn}",
          "${aws_s3_bucket.NukeS3Bucket.arn}/*"
        ],
        "Condition" : {
          "Bool" : {
            "aws:SecureTransport" : "false"
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic" "NukeEmailTopic" {
  display_name      = "NukeTopic"
  fifo_topic        = false
  kms_master_key_id = "alias/aws/sns"
  name              = var.NukeTopicName

  tags = {
    "DoNotNuke" = "True"
    "owner"     = var.Owner
  }
}

resource "aws_lambda_function" "member_deprecation" {
  filename      = "member_deprecation.zip"
  function_name = "account_member_deprecation"
  role          = aws_iam_role.member_deprecation_role.arn

  source_code_hash = filebase64sha256("member_deprecation.zip")

  runtime = "python3.8"

  handler = "member_deprecation.lambda_handler"

}

resource "aws_iam_role" "member_deprecation_role" {
  name = "member_deprecation"

  assume_role_policy = jsonencode({

    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : "sts:AssumeRole",
        "Principal" : {
          "Service" : "lambda.amazonaws.com"
        },
        "Effect" : "Allow",
        "Sid" : ""
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "member_deprecation_policy_attachment" {
  name       = "member_deprecation_role_policy_attachment"
  roles      = [aws_iam_role.member_deprecation_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

resource "aws_iam_policy" "member_deprecation_policy_describeorganization" {
  name        = "describe_organization_policy"
  description = "Allows Lambda function to describe organization"

  policy = jsonencode({

    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "AllowDescribeOrganization",
        "Effect" : "Allow",
        "Action" : "organizations:DescribeOrganization",
        "Resource" : "*"
      },
      {
        "Sid" : "AssumeRole",
        "Effect" : "Allow",
        "Action" : "sts:AssumeRole",
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "member_deprecation_policy_describeorganization_attachment" {
  role       = aws_iam_role.member_deprecation_role.name
  policy_arn = aws_iam_policy.member_deprecation_policy_describeorganization.arn
}

### Lambda Termination

resource "aws_lambda_function" "termination_flag" {
  filename      = "termination.zip"
  function_name = "termination_flag"
  role          = aws_iam_role.termination_flag_role.arn

  source_code_hash = filebase64sha256("termination.zip")

  runtime = "python3.8"

  handler = "termination.lambda_handler"

  timeout = 600

}

resource "aws_iam_role" "termination_flag_role" {
  name = "termination_flag_role"

  assume_role_policy = jsonencode({

    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : "sts:AssumeRole",
        "Principal" : {
          "Service" : "lambda.amazonaws.com"
        },
        "Effect" : "Allow",
        "Sid" : ""
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "termination_flag_role_attachment" {
  name       = "termination_flag_role_attachment"
  roles      = [aws_iam_role.termination_flag_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "termination_flag_role_attachment_policy" {
  name        = "additional_access_policy"
  description = "Allows Lambda function additional access"

  policy = jsonencode({

    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "AllowEC2FullAccess",
        "Effect" : "Allow",
        "Action" : "ec2:*",
        "Resource" : "*"
      },
      {
        "Sid" : "AllowRDSFullAccess",
        "Effect" : "Allow",
        "Action" : "rds:*",
        "Resource" : "*"
      },
      {
        "Sid" : "AllowEFSFullAccess",
        "Effect" : "Allow",
        "Action" : "elasticfilesystem:*",
        "Resource" : "*"
      },
      {
        "Sid" : "AllowELBFullAccess",
        "Effect" : "Allow",
        "Action" : "elasticloadbalancing:*",
        "Resource" : "*"
      },
      {
        "Sid" : "AllowElasticBeanstalkFullAccess",
        "Effect" : "Allow",
        "Action" : "elasticbeanstalk:*",
        "Resource" : "*"
      },
      {
        "Sid" : "AllowElasticMapReduceFullAccess",
        "Effect" : "Allow",
        "Action" : "elasticmapreduce:*",
        "Resource" : "*"
      },
      {
        "Sid" : "AllowCloudFormationFullAccess",
        "Effect" : "Allow",
        "Action" : "cloudformation:*",
        "Resource" : "*"
      },
      {
        "Sid" : "AllowDynamoDBFullAccess",
        "Effect" : "Allow",
        "Action" : "dynamodb:*",
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "additional_access_policy_attachment" {
  role       = aws_iam_role.termination_flag_role.name
  policy_arn = aws_iam_policy.termination_flag_role_attachment_policy.arn
}

#### Check Status Lambda

resource "aws_lambda_function" "calculate_nuke_result" {
  filename      = "calculate_nuke_result.zip"
  function_name = "calculate_nuke_result"
  role          = aws_iam_role.termination_flag_role.arn

  source_code_hash = filebase64sha256("calculate_nuke_result.zip")

  runtime = "python3.8"

  handler = "calculate_nuke_result.lambda_handler"

  timeout = 600

}

resource "aws_iam_role" "calculate_nuke_result_role" {
  name = "calculate_nuke_result_role"

  assume_role_policy = jsonencode({

    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : "sts:AssumeRole",
        "Principal" : {
          "Service" : "lambda.amazonaws.com"
        },
        "Effect" : "Allow",
        "Sid" : ""
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "calculate_nuke_result_role_attachment_lambda" {
  name       = "calculate_nuke_result_role_attachment_lambda"
  roles      = [aws_iam_role.calculate_nuke_result_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

resource "aws_iam_policy_attachment" "calculate_nuke_result_role_attachment_sf" {
  name       = "calculate_nuke_result_role_attachment_sf"
  roles      = [aws_iam_role.calculate_nuke_result_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AWSStepFunctionsFullAccess"
}

resource "aws_iam_policy_attachment" "calculate_nuke_result_role_attachment_account" {
  name       = "calculate_nuke_result_role_attachment_account"
  roles      = [aws_iam_role.calculate_nuke_result_role.name]
  policy_arn = "arn:aws:iam::aws:policy/AWSAccountManagementFullAccess"
}

### Step Function

resource "aws_iam_role" "NukeStepFunctionRole" {
  name = "nuke-account-cleanser-codebuild-state-machine-role"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : [
            "states.${data.aws_region.current.name}.amazonaws.com"
          ]
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
  path = "/"

  tags = {
    "Name" : "NukeStepFunctionRole"
  }
}

resource "aws_iam_policy" "NukeStepFunctionRolePolicy" {
  name = "nuke-account-cleanser-codebuild-state-machine-policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "codebuild:StartBuild",
          "codebuild:StopBuild",
          "codebuild:StartBuildBatch",
          "codebuild:StopBuildBatch",
          "codebuild:RetryBuild",
          "codebuild:RetryBuildBatch",
          "codebuild:BatchGet*",
          "codebuild:GetResourcePolicy",
          "codebuild:DescribeTestCases",
          "codebuild:DescribeCodeCoverages",
          "codebuild:List*"
        ],
        "Resource" : [
          aws_codebuild_project.NukeCodeBuildProject.arn
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "events:PutTargets",
          "events:PutRule",
          "events:DescribeRule"
        ],
        "Resource" : "arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/StepFunctionsGetEventForCodeBuildStartBuildRule"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "sns:Publish"
        ],
        "Resource" : [
          aws_sns_topic.NukeEmailTopic.arn
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "states:DescribeStateMachine",
          "states:ListExecutions",
          "states:StartExecution",
          "states:StopExecution",
          "states:DescribeExecution"
        ],
        "Resource" : "arn:aws:states:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stateMachine:nuke-account-cleanser-codebuild-state-machine"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "lambda:InvokeFunction"
        ]
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "NukeStepFunctionRolePolicyAttachment" {
  role       = aws_iam_role.NukeStepFunctionRole.name
  policy_arn = aws_iam_policy.NukeStepFunctionRolePolicy.arn
}

resource "aws_sfn_state_machine" "NukeStepFunction" {
  name     = "nuke-account-cleanser-codebuild-state-machine"
  role_arn = aws_iam_role.NukeStepFunctionRole.arn

  definition = jsonencode(
    {
    "Comment": "AWS Nuke Account Cleanser for multi-region single account clean up using SFN Map state parallel invocation of CodeBuild project.",
    "StartAt": "FlagTermination",
    "States": {
      "FlagTermination": {
        "Catch": [
          {
            "ErrorEquals": [
              "States.ALL"
            ],
            "Next": "StartNukeCodeBuildForEachRegion"
          }
        ],
        "Next": "StartNukeCodeBuildForEachRegion",
        "Parameters": {
          "FunctionName": "${aws_lambda_function.termination_flag.arn}:$LATEST",
          "Payload.$": "$"
        },
        "Resource": "arn:aws:states:::lambda:invoke",
        "ResultPath": null,
        "Retry": [
          {
            "BackoffRate": 2,
            "ErrorEquals": [
              "Lambda.ServiceException",
              "Lambda.AWSLambdaException",
              "Lambda.SdkClientException",
              "Lambda.TooManyRequestsException"
            ],
            "IntervalSeconds": 2,
            "MaxAttempts": 6
          }
        ],
        "Type": "Task"
      },
      "StartNukeCodeBuildForEachRegion": {
        "ItemsPath": "$.InputPayLoad.region_list",
        "Iterator": {
          "StartAt": "Trigger Nuke CodeBuild Job",
          "States": {
            "Check Nuke CodeBuild Job Status": {
              "Choices": [
                {
                  "Next": "Nuke Success",
                  "StringEquals": "SUCCEEDED",
                  "Variable": "$.AccountCleanserRegionOutput.NukeBuildOutput.BuildStatus"
                },
                {
                  "Next": "Nuke Failed",
                  "StringEquals": "FAILED",
                  "Variable": "$.AccountCleanserRegionOutput.NukeBuildOutput.BuildStatus"
                }
              ],
              "Default": "Nuke Success",
              "Type": "Choice"
            },
            "Nuke Failed": {
              "End": true,
              "Parameters": {
                "CodeBuild Status.$": "States.Format('Nuke Account Cleanser failed with error {}. Check CodeBuild execution for input region {} to investigate', $.AccountCleanserRegionOutput.Error, $.region_id)",
                "Region.$": "$.region_id",
                "Status": "Failed"
              },
              "ResultPath": "$.result",
              "Type": "Pass"
            },
            "Nuke Success": {
              "Parameters": {
                "CodeBuild Status.$": "$.AccountCleanserRegionOutput.NukeBuildOutput.BuildStatus",
                "Region.$": "$.region_id",
                "Status": "Succeeded"
              },
              "ResultPath": "$.result",
              "Type": "Pass",
              "End": true
            },
            "Trigger Nuke CodeBuild Job": {
              "Catch": [
                {
                  "ErrorEquals": [
                    "States.ALL"
                  ],
                  "Next": "Nuke Failed",
                  "ResultPath": "$.AccountCleanserRegionOutput"
                }
              ],
              "Next": "Check Nuke CodeBuild Job Status",
              "Parameters": {
                "EnvironmentVariablesOverride": [
                  {
                    "Name": "NukeTargetRegion",
                    "Type": "PLAINTEXT",
                    "Value.$": "$.region_id"
                  },
                  {
                    "Name": "AWS_NukeDryRun",
                    "Type": "PLAINTEXT",
                    "Value.$": "$.nuke_dry_run"
                  },
                  {
                    "Name": "AWS_NukeVersion",
                    "Type": "PLAINTEXT",
                    "Value.$": "$.nuke_version"
                  }
                ],
                "ProjectName": "${aws_codebuild_project.NukeCodeBuildProject.arn}"
              },
              "Resource": "arn:aws:states:::codebuild:startBuild.sync",
              "ResultPath": "$.AccountCleanserRegionOutput",
              "ResultSelector": {
                "NukeBuildOutput.$": "$.Build"
              },
              "Retry": [
                {
                  "BackoffRate": 1,
                  "ErrorEquals": [
                    "States.TaskFailed"
                  ],
                  "IntervalSeconds": 1,
                  "MaxAttempts": 1
                }
              ],
              "Type": "Task"
            }
          }
        },
        "MaxConcurrency": 5,
        "Next": "CalculateNukeResult",
        "Parameters": {
          "nuke_dry_run.$": "$.InputPayLoad.nuke_dry_run",
          "nuke_version.$": "$.InputPayLoad.nuke_version",
          "region_id.$": "$$.Map.Item.Value"
        },
        "ResultPath": "$.NukeFinalMapAllRegionsOutput",
        "ResultSelector": {
          "filteredResult.$": "$..result"
        },
        "Type": "Map"
      },
      "CalculateNukeResult": {
        "Type": "Task",
        "Resource": "arn:aws:states:::lambda:invoke",
        "OutputPath": "$.Payload",
        "Parameters": {
          "Payload.$": "$",
          "FunctionName": "${aws_lambda_function.calculate_nuke_result.arn}:$LATEST"
        },
        "Retry": [
          {
            "ErrorEquals": [
              "Lambda.ServiceException",
              "Lambda.AWSLambdaException",
              "Lambda.SdkClientException",
              "Lambda.TooManyRequestsException"
            ],
            "IntervalSeconds": 2,
            "MaxAttempts": 6,
            "BackoffRate": 2
          }
        ],
        "Next": "Choice"
      },
      "Choice": {
        "Type": "Choice",
        "Choices": [
          {
            "Variable": "$.NukeFinal.Status",
            "StringMatches": "Succeeded",
            "Next": "Lambda Invoke"
          }
        ],
        "Default": "Clean Output and Notify"
      },
      "Lambda Invoke": {
        "Parameters": {
          "FunctionName": "${aws_lambda_function.member_deprecation.arn}:$LATEST",
          "Payload.$": "$"
        },
        "Resource": "arn:aws:states:::lambda:invoke",
        "Retry": [
          {
            "BackoffRate": 2,
            "ErrorEquals": [
              "Lambda.ServiceException",
              "Lambda.AWSLambdaException",
              "Lambda.SdkClientException",
              "Lambda.TooManyRequestsException"
            ],
            "IntervalSeconds": 2,
            "MaxAttempts": 6
          }
        ],
        "Type": "Task",
        "Next": "Clean Output and Notify",
        "OutputPath": "$.Payload"
      },
      "Clean Output and Notify": {
        "End": true,
        "Parameters": {
          "Message": "Nuke Account Cleanser completed for input payload",
          "Subject": "State Machine for Nuke Account Cleanser completed",
          "TopicArn": "${aws_sns_topic.NukeEmailTopic.arn}"
        },
        "Resource": "arn:aws:states:::sns:publish",
        "Type": "Task"
      }
    }
  }
  )
  tags = {
    DoNotNuke = "True"
    "owner"   = var.Owner
  }
}

output "NukeTopicArn" {
  description = "Arn of SNS Topic used for notifying nuke results in email"
  value       = aws_sns_topic.NukeEmailTopic.arn
}

output "NukeS3BucketValue" {
  description = "S3 bucket created with the random generated name"
  value       = aws_s3_bucket.NukeS3Bucket.id
}

