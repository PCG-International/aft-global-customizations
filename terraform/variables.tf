variable "BucketName" {
  type        = string
  description = "BucketName"
  default     = "bucketnuke"
}

variable "NukeCleanserRoleName" {
  type        = string
  description = "NukeCleanserRoleName"
  default     = "nuke-auto-account-cleanser"
}

variable "IAMPath" {
  type        = string
  description = "IAMPath"
  default     = "/"
}

variable "AWSNukeDryRunFlag" {
  type        = string
  description = "AWSNukeDryRunFlag"
  default     = "true"
}

variable "AWSNukeVersion" {
  type        = string
  description = "AWSNukeVersion"
  default     = "2.21.2"
}

variable "NukeTopicName" {
  type        = string
  description = "NukeTopicName"
  default     = "SNSTopicNuke"
}

variable "Owner" {
  type        = string
  description = "OpsAdmin"
  default     = "OpsAdmin"
}

variable "stack_name" {
  type        = string
  description = "Name of this stack"
  default     = "NukeStack"
}

