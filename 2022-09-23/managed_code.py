# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

import base64
import csv
import json
from io import StringIO
import re

from botocore.exceptions import ClientError
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

import adal
import pandas as pd
import numpy as np
import netaddr
import googleapiclient.discovery

import itertools
from ipaddress import ip_network
from pandas.io import json as pd_json
from copy import deepcopy
import requests
from adal.adal_error import AdalError
from bson import ObjectId
from dateutil.parser import parse
from dateutil.relativedelta import relativedelta

from cs_policy_interface.aws_utils import run_aws_operation
from cs_policy_interface.definitions import AzureUtils
from cs_policy_interface.definitions import GCPUtils
from cs_policy_interface.definitions import HTTPCODES
from cs_policy_interface.definitions import NetworkConfigurationAccess
from cs_policy_interface.definitions import services_protocol_port
from cs_policy_interface.gcp_utils import run_big_query_job, run_bigquery_job_for_oauth2_type, get_credential
from cs_policy_interface.utils import AccessNestedDict
from cs_policy_interface.utils import get_mongo_client


class ManagedCode(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def cloud_account_budget(self, service_account_id, budget_scope):
        output = list()
        response = OrderedDict()
        try:
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            query = [{"$match": {"service_account_id": service_account_id,
                                 "mapped_template_id": {"$exists": True, "$ne": "NA"}}},
                     {"$project": {"mapped_template_id": 1, "_id": 0}}]
            budget_result = list(db.budget.aggregate(query, cursor={}))
            budget_not_set = True
            if budget_result:
                mapped_template_id_list = [ObjectId(res["mapped_template_id"]) for res in budget_result if
                                           res.get("mapped_template_id")]
                scopes = list(db.budget_definition_template.aggregate(
                    [{"$match": {"_id": {"$in": mapped_template_id_list}}},
                     {"$project": {"budget_scope": 1, "_id": 0}}], cursor={}))
                if scopes:
                    for scope in scopes:
                        if budget_scope in scope.values():
                            budget_not_set = False
                            break
            if budget_not_set:
                response.update(ResourceId=None,
                                BudgetType="COST",
                                Scope=budget_scope,
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name'])
                output.append(response)
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def list_azure_ea_billing_period(self, enrollment_id, api_key):
        try:
            endpoint = "https://consumption.azure.com/v2/enrollments/%s/billingperiods" % enrollment_id
            header = {"Content-Type": "application/json", "Authorization": "Bearer %s" % api_key}
            response = requests.get(endpoint, headers=header, timeout=30)
            return response
        except Exception as e:
            raise Exception(str(e))

    def azure_validate_application_secret_key(self):
        output = []
        credentials = dict()
        try:
            credentials = self.execution_args['auth_values']
            if credentials.get("protocol") == 'api_key':
                response = self.list_azure_ea_billing_period(credentials.get("enrollment_id"),
                                                             credentials.get("api_key"))
                if response.status_code != HTTPCODES.SUCCESS:
                    response_content = json.loads(response.content)
                    error_message = response_content.get("error", {}).get("message")
                    error_dict = dict(ResourceId=credentials["enrollment_id"],
                                      ResourceName=credentials["enrollment_id"],
                                      ResourceType='api_key',
                                      Error=error_message)
                    output.append(error_dict)
                return output, len(output)
            else:
                endpoint = AzureUtils.ENDPOINT.get(credentials["cloud_type"])
                context = adal.AuthenticationContext(endpoint.get("AUTHENTICATION_ENDPOINT") + credentials['tenant_id'])
                token_response = context. \
                    acquire_token_with_client_credentials(endpoint.get("RESOURCE"),
                                                          credentials['application_id'],
                                                          credentials['application_secret'])
                if token_response.get('accessToken'):
                    return output, len(output)
        except AdalError as e:
            error_description = e.error_response["error_description"] if isinstance(e.error_response,
                                                                                    dict) else e.error_response
            error_description = error_description.split(":")
            error_code = error_description[0]
            error_msg = AzureUtils.error_mapping.get(error_code, "The provided application secret is invalid.")
            error_dict = dict(ResourceId=credentials["application_id"],
                              ResourceName=credentials["application_id"],
                              ResourceType='application_secret',
                              Error=error_msg)
            output.append(error_dict)
            return output, len(output)
        except Exception as e:
            raise Exception(str(e))

    # def forecasted_amount_exceeded_budget(self, **kwargs):
    #     try:
    #         output = list()
    #         service_account_id = self.execution_args["service_account_id"]
    #         db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
    #         budget_query = {"service_account_id": service_account_id}
    #         budget_query['budget_frequency'] = 'monthly'
    #         budgets = db.budget_v2.find(budget_query)
    #         if budgets.count():
    #             set_budget = projected = 'undefined'
    #             current_month = datetime.today().strftime('%Y-%m')
    #             projected_cost = db.account_summary.find_one({"service_account_id": ObjectId(service_account_id),
    #                                                           "day.month": current_month})
    #             if projected_cost and projected_cost.get("day"):
    #                 projected = projected_cost["day"][0].get("projected_cost")
    #             for budget in budgets:
    #                 if budget and budget.get("summary").get("budget_amount").get("amount"):
    #                     set_budget = budget["summary"]["budget_amount"]["amount"]
    #                 if (projected != 'undefined' and budget != 'undefined') and projected > float(set_budget):
    #                     set_budget = float(set_budget)
    #                     percentage = ((projected - set_budget) / projected) * 100
    #                     if percentage > 50:
    #                         response = dict(ResourceId=budget.get("budget_name", ""),
    #                                         ResourceType="Budget",
    #                                         BudgetType=budget.get("budget_type").upper(),
    #                                         ForecastedCost=projected,
    #                                         Budget=set_budget)
    #                         output.append(response)
    #         return output, budgets.count()
    #     except Exception as e:
    #         raise Exception(str(e))
    #
    # def actual_amount_exceeded_budget(self, **kwargs):
    #     try:
    #         service_account_id = self.execution_args["service_account_id"]
    #         output = list()
    #         db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
    #         set_actual_cost = set_budget = 'undefined'
    #         budget_query = {"service_account_id": service_account_id}
    #         budget_query['budget_frequency'] = 'monthly'
    #         budgets = db.budget_v2.find(budget_query)
    #         if budgets.count():
    #             last_month = (datetime.today() - relativedelta(months=+1)).strftime('%Y-%m')
    #             cost_details = db.account_summary.find_one({"service_account_id": ObjectId(service_account_id),
    #                                                         "month.by_month.month": last_month})
    #             if cost_details and cost_details.get("month"):
    #                 actual_costs = cost_details["month"][0].get("by_month", [])
    #                 for cost in actual_costs:
    #                     if cost.get("month") == last_month:
    #                         set_actual_cost = cost.get("total_cost")
    #                         break
    #             for budget in budgets:
    #                 if budget and budget.get("summary").get("budget_amount").get("amount"):
    #                     set_budget = budget["summary"]["budget_amount"]["amount"]
    #                 if (set_actual_cost != 'undefined' and set_budget != 'undefined') and set_actual_cost > float(
    #                         set_budget):
    #                     percentage = ((set_actual_cost - float(set_budget)) / float(set_budget)) * 100
    #                     if percentage > 30:
    #                         response = dict(ResourceId=budget.get("budget_name", ""),
    #                                         ResourceType="Budget",
    #                                         BudgetType=budget.get("budget_type").upper(),
    #                                         ActualCost=set_actual_cost,
    #                                         Budget=float(set_budget))
    #                         output.append(response)
    #         return output, budgets.count()
    #     except Exception as e:
    #         raise Exception(str(e))
    #
    # def aws_account_level_budget(self, **kwargs):
    #     try:
    #         output, total = self.cloud_account_budget(self.execution_args["service_account_id"], "Account")
    #         return output, total
    #     except Exception as e:
    #         raise Exception(str(e))
    #
    # def aws_region_level_budget(self, **kwargs):
    #     try:
    #         output, total = self.cloud_account_budget(self.execution_args["service_account_id"], "Region")
    #         return output, total
    #     except Exception as e:
    #         raise Exception(str(e))

    def azure_resource_group_level_budget(self, **kwargs):
        try:
            output, total = self.cloud_account_budget(self.execution_args["service_account_id"], "Resource_Group")
            return output, total
        except Exception as e:
            raise Exception(str(e))

    def azure_subscription_level_budget(self, **kwargs):
        try:
            output, total = self.cloud_account_budget(self.execution_args["service_account_id"], "Subscription")
            return output, total
        except Exception as e:
            raise Exception(str(e))

    def check_cloud_trails(self, **kwargs):
        output = list()
        regions_list = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = run_aws_operation(credentials, 'ec2', 'describe_regions', response_key="Regions",
                                        region_name='us-east-1')
            if regions:
                regions_list = regions["Regions"]
                for region in regions_list:
                    trails = run_aws_operation(credentials, 'cloudtrail', 'list_trails',
                                               region_name=region["RegionName"], response_key="Trails")
                    if len(trails) > 1:
                        trail_name = list()
                        for trail in trails:
                            trail_name.append(trail["Name"])
                        output.append(OrderedDict(ResourceId=None,
                                                  ResourceName=None,
                                                  Resource=None,
                                                  ServiceAccountId=service_account_id,
                                                  Region=region["RegionName"],
                                                  ServiceAccountName=self.execution_args['service_account_name'],
                                                  CloudTrailNames=", ".join(trail_name)))
            return output, len(regions_list)
        except Exception as e:
            raise Exception(str(e))

    def aws_savings_plans(self, **kwargs):
        output = list()
        response = dict()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            operation_args = {"LookbackPeriodInDays": "SIXTY_DAYS"}
            savings_plans_types = ["COMPUTE_SP", "EC2_INSTANCE_SP"]
            payment_options = ['NO_UPFRONT', 'PARTIAL_UPFRONT', 'ALL_UPFRONT']
            term_in_years = ['ONE_YEAR', 'THREE_YEARS']
            recommendation_list = list()
            for savings_plans_type in savings_plans_types:
                operation_args.update(SavingsPlansType=savings_plans_type)
                for payment_option in payment_options:
                    operation_args.update(PaymentOption=payment_option)
                    for term_in_year in term_in_years:
                        operation_args.update(TermInYears=term_in_year)
                        recommendations = run_aws_operation(credentials, 'ce',
                                                            'get_savings_plans_purchase_recommendation',
                                                            operation_args=operation_args)
                        if recommendations.get("SavingsPlansPurchaseRecommendation"):
                            recommendation_list.extend(recommendations.get("SavingsPlansPurchaseRecommendation"))
            if recommendation_list:
                savings_plans_data = run_aws_operation(credentials, 'savingsplans', 'describe_savings_plans')
                savings_plans = savings_plans_data.get("savingsPlans") if savings_plans_data else []
                if not savings_plans:
                    response.update(ResourceId=None,
                                    ResourceName=None,
                                    Resource=None,
                                    ServiceAccountID=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']
                                    )
                    output.append(response)
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def aws_workspace_unused(self, **kwargs):
        output = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            elapsed_days = self.execution_args['args'].get("ElapsedDays")
            billing_db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            inventory_db = get_mongo_client(self.connection_args)['resource_inventory']
            check_date = datetime.utcnow() - timedelta(days=int(elapsed_days))
            check_date = check_date.replace(hour=00, minute=00, second=00, microsecond=00)
            query = [
                {"$match": {"service_account_id": service_account_id,
                            "start_date": {"$gte": check_date, "$lte": datetime.utcnow()}}},
                {
                    "$group": {
                        "_id": "$resource_id",
                        "count": {"$sum": 1},
                        "billable_hours": {"$sum": "$used_hours"}
                    }
                },
                {"$match": {"count": {"$gte": int(elapsed_days) - 1}}}
            ]
            results = billing_db['workspace_utilization_daily'].aggregate(query, cursor={})
            evaluated_resources = 0
            for result in results:
                resource_id = result["_id"]
                inventory_query = {
                    "service_account_id": service_account_id,
                    "check_resource_element": resource_id,
                    "resource": self.execution_args.get("resource"),
                    "is_deleted": False
                }
                resource_details = inventory_db["service_resource_inventory"].find_one(inventory_query)
                if resource_details:
                    evaluated_resources += 1
                    resource_properties = resource_details.get("summary_details", {}).get("WorkspaceProperties", {})
                    bundle_type = resource_properties.get("ComputeTypeName", "")
                    billable_hours = int(result.get("billable_hours", 0))
                    if not billable_hours:
                        response = {"ResourceId": resource_id,
                                    "ResourceName": resource_details.get("summary_details", {}).get("ComputerName", ""),
                                    "ResourceType": resource_details.get("resource_type", ""),
                                    "DirectoryId": resource_details.get("summary_details", {}).get("DirectoryId", ""),
                                    "BundleType": bundle_type,
                                    "Region": resource_details.get("resource_filter", "")
                                    }
                        output.append(response)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_workspace_recommendation(self, **kwargs):
        output = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            value_limit = self.execution_args['args'].get("ValueLimit")
            standard_limit = self.execution_args['args'].get("StandardLimit")
            performance_limit = self.execution_args['args'].get("PerformanceLimit")
            power_limit = self.execution_args['args'].get("PowerLimit")
            power_pro_limit = self.execution_args['args'].get("PowerProLimit")
            graphics_limit = self.execution_args['args'].get("GraphicsLimit")
            graphics_pro_limit = self.execution_args['args'].get("GraphicsProLimit")
            billing_db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            inventory_db = get_mongo_client(self.connection_args)['resource_inventory']
            check_date = datetime.utcnow().replace(day=1, hour=00, minute=00, second=00, microsecond=00)
            query = [
                {"$match": {"service_account_id": service_account_id,
                            "start_date": {"$gte": check_date, "$lte": datetime.utcnow()}}},
                {
                    "$group": {
                        "_id": "$resource_id",
                        "billable_hours": {"$sum": "$used_hours"}
                    }
                }
            ]
            results = billing_db['workspace_utilization_daily'].aggregate(query, cursor={})
            evaluated_resources = 0
            for result in results:
                resource_id = result["_id"]
                inventory_query = {
                    "service_account_id": service_account_id,
                    "check_resource_element": resource_id,
                    "is_deleted": False
                }
                resource_details = inventory_db["service_resource_inventory"].find_one(inventory_query)
                if resource_details:
                    evaluated_resources += 1
                    resource_properties = resource_details.get("summary_details", {}).get("WorkspaceProperties", {})
                    bundle_type = resource_properties.get("ComputeTypeName", "")
                    running_mode = resource_properties.get("RunningMode")
                    billable_hours = int(result.get("billable_hours", 0))
                    response = {"ResourceId": resource_id,
                                "ResourceName": resource_details.get("summary_details", {}).get("ComputerName", ""),
                                "ResourceType": resource_details.get("resource_type", ""),
                                "DirectoryId": resource_details.get("summary_details", {}).get("DirectoryId", ""),
                                "BundleType": bundle_type,
                                "InitialRunningMode": running_mode,
                                "BillableHours": str(billable_hours),
                                "Region": resource_details.get("resource_filter", ""),
                                }
                    if bundle_type == "VALUE":
                        response["UsageThreshold"] = value_limit
                    elif bundle_type == "STANDARD":
                        response["UsageThreshold"] = standard_limit
                    elif bundle_type == "PERFORMANCE":
                        response["UsageThreshold"] = performance_limit
                    elif bundle_type == "POWER":
                        response["UsageThreshold"] = power_limit
                    elif bundle_type == "POWERPRO":
                        response["UsageThreshold"] = power_pro_limit
                    elif bundle_type == "GRAPHICS":
                        response["UsageThreshold"] = graphics_limit
                    elif bundle_type == "GRAPHICSPRO":
                        response["UsageThreshold"] = graphics_pro_limit
                    change_recommended = recommended_mode = "NA"
                    if billable_hours > response["UsageThreshold"]:
                        change_recommended = "Yes" if running_mode == "AUTO_STOP" else "NO"
                        recommended_mode = "ALWAYS_ON"
                    elif billable_hours <= response["UsageThreshold"]:
                        change_recommended = "Yes" if running_mode == "ALWAYS_ON" else "NO"
                        recommended_mode = "AUTO_STOP"
                    response.update({"ChangeRecommended": change_recommended,
                                     "RecommendedMode": recommended_mode})
                    output.append(response)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def reservation_expiry(self, reservation_type):
        output = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            no_of_days = self.execution_args['args'].get("No_of_days", 30)
            date = (datetime.today() - relativedelta(days=-no_of_days))
            query = {"service_account_id": service_account_id, "expiry_date": {"$lte": date},
                     "reservation_type": reservation_type}
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            results = db['ri_summary'].find(query)
            count = db['ri_summary'].find({"service_account_id": service_account_id,
                                           "reservation_type": reservation_type}).count()
            for result in results:
                response = OrderedDict(ResourceId=result.get("reservation_id"),
                                       ResourceName=result.get("reservation_name"),
                                       ReservationType=result.get("reservation_type"),
                                       ExpiryDate=result.get("expiry_date"))
                output.append(response)
            return output, count
        except Exception as e:
            raise Exception(str(e))

    def azure_recently_purchased_reservations(self, **kwargs):
        output = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            no_of_days = self.execution_args.get('args', {}).get("No_of_days", 7)
            date = (datetime.utcnow() - relativedelta(days=no_of_days))
            query = {"service_account_id": service_account_id, "purchased_date": {"$gte": date}}
            db = get_mongo_client(self.connection_args)[self.connection_args.get('database_name')]
            results = db['ri_summary'].find(query)
            count = db['ri_summary'].find({"service_account_id": service_account_id}).count()
            for result in results:
                response = OrderedDict([('ProjectName', result.get("project_name")),
                                        ('ServiceAccountName', self.execution_args['service_account_name']),
                                        ('ServiceAccountID', result.get("service_account_id")),
                                        ('ResourceId', result.get("reservation_id")),
                                        ('ResourceName', result.get("reservation_name")),
                                        ('ResourceType', "Reserved_VM_Instances"),
                                        ('ReservationType', result.get("reservation_type")),
                                        ('PurchasedDate', result.get("purchased_date")),
                                        ('ExpiryDate', result.get("expiry_date")),
                                        ('IsActive', result.get("is_active"))])
                output.append(response)
            return output, count
        except Exception as e:
            raise Exception(str(e))

    def azure_virtual_machine_reservation_expiry(self, **kwargs):
        try:
            output, count = self.reservation_expiry('VirtualMachines')
            return output, count
        except Exception as e:
            raise Exception(str(e))

    def audit_recently_created_deleted_inventory_resources(self, **kwargs):
        output = list()
        evaluated_resources = 0
        service_account_id = self.execution_args.get("service_account_id")
        number_of_days = self.execution_args.get('args', {}).get("Number_of_Days", 1)
        date = (datetime.utcnow() - relativedelta(days=number_of_days)).replace(hour=00, minute=00, second=00,
                                                                                microsecond=00)
        try:
            query = {
                "service_account_id": service_account_id,
                "$or": [
                    {"created_at": {"$gte": date}, "is_deleted": False},
                    {"updated_at": {"$gte": date}, "is_deleted": True}
                ]
            }
            db = get_mongo_client(self.connection_args)[self.connection_args.get('database_name')]
            results = db['service_resource_inventory'].find(query)
            for result in results:
                evaluated_resources += 1
                output.append(
                    OrderedDict([
                        ('ServiceAccountName', result['service_account_name']),
                        ('ServiceAccountID', result["service_account_id"]),
                        ('ResourceId', result["check_resource_element"]),
                        ('Category', result["category"]),
                        ('Resource', result["resource"]),
                        ('ResourceType', result["resource_type"]),
                        ('Location', result["location"]),
                        ('Status', "Deleted" if result["is_deleted"] else "New")
                    ]))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def azure_audit_nsg_custom_rules(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            match_query = {"service_account_id": service_account_id, "category": "Network",
                           "resource": "Network_Security_Group",
                           "summary_details.properties.securityRules": {"$exists": True, "$ne": []},
                           "is_deleted": False}
            db = get_mongo_client(self.connection_args)[self.connection_args.get('database_name')]
            results = db['service_resource_inventory'].find(match_query)
            for result in results:
                for sg_rule in result.get("summary_details", {}).get("properties", {}).get("securityRules", []):
                    properties = sg_rule.get("properties", {})
                    if properties.get("provisioningState") != "Succeeded":
                        continue
                    evaluated_resources += 1
                    output.append(
                        OrderedDict([
                            ('ServiceAccountName', self.execution_args['service_account_name']),
                            ('ServiceAccountID', result.get("service_account_id")),
                            ('ResourceId', sg_rule.get("id")),
                            ('ResourceName', sg_rule.get("name")),
                            ('ResourceType', "Security_Rule"),
                            ('ResourceGroup', result.get("resource_filter")),
                            ('Location', result.get("location")),
                            ('SecurityGroupName', result.get("summary_details", {}).get("name")),
                            ('SecurityGroupID', result.get("summary_details", {}).get("id")),
                            ('Direction', properties.get("direction")),
                            ('Access', properties.get("access")),
                            ('Protocol', properties.get("protocol")),
                            ('SourcePortRange', properties.get("sourcePortRange", properties.get("sourcePortRanges"))),
                            ('DestinationPortRange',
                             properties.get("destinationPortRange", properties.get("destinationPortRanges"))),
                            ('Description', properties.get("description")),
                            ('SourceAddressPrefix',
                             properties.get("sourceAddressPrefix", properties.get("sourceAddressPrefixes"))),
                            ('DestinationAddressPrefix',
                             properties.get("destinationAddressPrefix", properties.get("destinationAddressPrefixes"))),
                            ('Priority', properties.get("priority"))
                        ]))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_reservation_expiry(self, **kwargs):
        try:
            output, count = self.reservation_expiry('Amazon Elastic Compute Cloud - Compute')
            return output, count
        except Exception as e:
            raise Exception(str(e))

    def azure_sql_reservation_expiry(self, **kwargs):
        try:
            output, count = self.reservation_expiry('Databases')
            return output, count
        except Exception as e:
            raise Exception(str(e))

    def check_vulnerability_in_vm(self, **kwargs):
        try:
            output = list()
            count = 0
            service_account_id = self.execution_args["service_account_id"]
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            results = db['security_findings'].find({
                "service_account_id": ObjectId(service_account_id),
                "service_name": self.execution_args['service_name'],
                "status": "active", "severity": {"$in": ["Critical", "HIGH"]}})
            for result in results:
                output_response = OrderedDict(
                    ResourceId=result.get("findings_data", {}).get("ResourceId"),
                    ResourceName=result.get("resource_name"),
                    ResourceType=result.get("resource_type")
                )
                output.append(output_response)
            return output, count
        except Exception as e:
            raise Exception(str(e))

    def check_iam_user_password_policy(self, **kwargs):
        output = list()
        try:
            service_account_id = self.execution_args.get('service_account_id')
            credentials = self.execution_args['auth_values']
            try:
                iam = run_aws_operation(
                    credentials, 'iam', 'get_account_password_policy')
            except ClientError as e:
                if 'NoSuchEntity' in str(e):
                    output.append(
                        OrderedDict(
                            ResourceId="",
                            ResourceName="",
                            ResourceType="IAM_Users",
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name']))
                else:
                    raise Exception(str(e))
            else:
                if 'PasswordPolicy' not in iam or not iam.get('PasswordPolicy', {}).get('ExpirePasswords'):
                    output.append(
                        OrderedDict(
                            ResourceId="",
                            ResourceName="",
                            ResourceType="IAM_Users",
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name']))
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def check_api_gateway(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rest_apis = run_aws_operation(
                        credentials,
                        'apigateway',
                        'get_rest_apis',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for api in rest_apis.get('items'):
                    evaluated_resources += 1
                    operation_args = dict(restApiId=api.get('id'))
                    stages = run_aws_operation(
                        credentials,
                        'apigateway',
                        'get_stages',
                        operation_args,
                        region_name=region)
                    for stage in stages.get('item', {}):
                        if not stage.get('clientCertificateId'):
                            output.append(
                                OrderedDict(
                                    ResourceId=api.get('name'),
                                    ResourceName=api.get('name'),
                                    ResourceType='ApiGateway_RestApi'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_sns_subscription(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    subscriptions = run_aws_operation(
                        credentials,
                        'sns',
                        'list_subscriptions',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for subscription in subscriptions.get('Subscriptions', {}):
                    operation_args = dict(SubscriptionArn=subscription.get('SubscriptionArn'))
                    subscription_attributes = run_aws_operation(
                        credentials,
                        'sns',
                        'get_subscription_attributes',
                        operation_args,
                        region_name=region)
                    evaluated_resources.append(subscriptions)
                    if subscription_attributes.get('Attributes', {}).get('Protocol') != 'http':
                        output.append(
                            OrderedDict(
                                ResourceId=subscription.get('SubscriptionArn'),
                                ResourceName=subscription.get('SubscriptionArn'),
                                Resource='SNS',
                                Region=region,
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def check_snapshot_permission(self, **kwargs):
        start_time = datetime.now()
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                if (datetime.now() - start_time).total_seconds() >= 1800:
                    break
                try:
                    snapshots = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_snapshots',
                        operation_args={
                            'Filters': [
                                {
                                    'Name': 'status',
                                    'Values': ['completed']
                                }
                            ],
                            'OwnerIds': ['self']
                        },
                        region_name=region,
                        response_key='Snapshots')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for snapshot in snapshots:
                    if (datetime.now() - start_time).total_seconds() >= 1800:
                        break
                    evaluated_resources += 1
                    try:
                        snapshots_attributes = run_aws_operation(
                            credentials,
                            'ec2',
                            'describe_snapshot_attribute',
                            region_name=region,
                            operation_args={
                                'Attribute': 'createVolumePermission',
                                'SnapshotId': snapshot.get('SnapshotId')})
                    except ClientError as e:
                        if "InvalidSnapshot" in str(e):
                            continue
                        raise Exception(str(e))
                    else:
                        for volume_permission in snapshots_attributes.get('CreateVolumePermissions', []):
                            if volume_permission.get('Group') == 'all':
                                output.append(
                                    OrderedDict(
                                        ResourceId=snapshot.get('SnapshotId'),
                                        ResourceName=snapshot.get('SnapshotId'),
                                        ResourceType='Snapshots'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_rds_cluster_encryption(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_cluster_info = run_aws_operation(
                        credentials, 'rds', 'describe_db_clusters', region_name=region,
                        response_key='DBClusters')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for rds_cluster in rds_cluster_info:
                    evaluated_resources += 1
                    if not rds_cluster.get('StorageEncrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=rds_cluster.get('DbClusterResourceId'),
                                ResourceName=rds_cluster.get('DBClusterIdentifier'),
                                ResourceType='DBInstance',
                                Region=region))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_rds_snapshots_encryption(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_snapshots_info = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_snapshots',
                        region_name=region,
                        response_key='DBSnapshots')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for snapshot in rds_snapshots_info:
                    evaluated_resources += 1
                    if not snapshot.get('Encrypted'):
                        output.append(OrderedDict(
                            ResourceId=snapshot.get('DBSnapshotIdentifier'),
                            ResourceName=snapshot.get('DBSnapshotIdentifier'),
                            ResourceType='DBClusterSnapshot'
                        ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_emr_data_encryption_at_rest(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    emr_security_configuration = run_aws_operation(
                        credentials,
                        'emr',
                        'list_security_configurations',
                        region_name=region,
                        response_key='SecurityConfigurations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for security_config_list in emr_security_configuration:
                    evaluated_resources += 1
                    security_info = run_aws_operation(
                        credentials,
                        'emr',
                        'describe_security_configuration',
                        operation_args={
                            'Name': security_config_list.get('Name')},
                        region_name=region)
                    check_data_encrypt = json.loads(
                        security_info.get('SecurityConfiguration'))
                    if not check_data_encrypt.get('EncryptionConfiguration', {}).get('EnableAtRestEncryption'):
                        output.append(
                            OrderedDict(
                                ResourceId=security_config_list.get('Name'),
                                ResourceName=security_config_list.get('Name'),
                                ResourceType='SecurityConfiguration'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_emr_data_encryption_at_transit(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    emr_security_configuration = run_aws_operation(
                        credentials,
                        'emr',
                        'list_security_configurations',
                        response_key='SecurityConfigurations',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for security_config_list in emr_security_configuration:
                    evaluated_resources += 1
                    security_info = run_aws_operation(
                        credentials,
                        'emr',
                        'describe_security_configuration',
                        operation_args={
                            'Name': security_config_list.get('Name')},
                        region_name=region)
                    check_data_encrypted = json.loads(
                        security_info.get('SecurityConfiguration'))
                    if not check_data_encrypted.get('EncryptionConfiguration', {}).get('EnableInTransitEncryption'):
                        output.append(
                            OrderedDict(
                                ResourceId=security_config_list.get('Name'),
                                ResourceName=security_config_list.get('Name'),
                                ResourceType='SecurityConfiguration'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_emr_local_disk_encryption(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    emr_security_configuration = run_aws_operation(
                        credentials,
                        'emr',
                        'list_security_configurations',
                        region_name=region,
                        response_key='SecurityConfigurations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for security_config_list in emr_security_configuration:
                    evaluated_resources += 1
                    security_info = run_aws_operation(
                        credentials,
                        'emr',
                        'describe_security_configuration',
                        operation_args={
                            'Name': security_config_list.get('Name')},
                        region_name=region)
                    check_data_encrypted = json.loads(
                        security_info['SecurityConfiguration'])
                    if not check_data_encrypted.get('EncryptionConfiguration', {}).get(
                            'AtRestEncryptionConfiguration', {}).get('LocalDiskEncryptionConfiguration'):
                        output.append(
                            OrderedDict(
                                ResourceId=security_config_list.get('Name'),
                                ResourceName=security_config_list.get('Name'),
                                ResourceType='SecurityConfiguration'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_elastic_cache_encryption(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elastic_cache_info = run_aws_operation(
                        credentials,
                        'elasticache',
                        'describe_cache_clusters',
                        response_key='CacheClusters',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for elastic_cache_cluster in elastic_cache_info:
                    evaluated_resources += 1
                    if not elastic_cache_cluster.get('AtRestEncryptionEnabled'):
                        output.append(
                            OrderedDict(
                                ResourceId=elastic_cache_cluster.get('CacheClusterId'),
                                ResourceName=elastic_cache_cluster.get('CacheClusterId'),
                                ResourceType='ElastiCache'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_redshift_audit_logging(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            operation_args = {}
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    redshift_cluster_name = run_aws_operation(
                        credentials, 'redshift', 'describe_clusters', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for cluster_info in redshift_cluster_name.get('Clusters'):
                    operation_args.update(ClusterIdentifier=cluster_info.get('ClusterIdentifier'))
                    evaluated_resources.append(
                        operation_args['ClusterIdentifier'])
                    logging_info = run_aws_operation(
                        credentials,
                        'redshift',
                        'describe_logging_status',
                        operation_args=operation_args,
                        region_name=region)
                    if not logging_info.get('LoggingEnabled'):
                        output.append(
                            OrderedDict(
                                ResourceId=cluster_info.get('ClusterIdentifier'),
                                ResourceName=cluster_info.get('ClusterIdentifier'),
                                Resource='AWS::Redshift::Cluster',
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def check_kinesis_streams_encrypted(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kinesis_streams_name = run_aws_operation(
                        credentials, 'kinesis', 'list_streams', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for kinesis_streams in kinesis_streams_name.get('StreamNames'):
                    credentials = self.execution_args['auth_values']
                    operation_args.update(StreamName=kinesis_streams)
                    evaluated_resources += 1
                    kinesis_info = run_aws_operation(
                        credentials,
                        'kinesis',
                        'describe_stream',
                        operation_args=operation_args,
                        region_name=region)
                    if kinesis_info.get('StreamDescription', {}).get(
                            'EncryptionType') == "NONE":
                        # Stream output "NONE" | KMS > if not customer managed key
                        output.append(
                            OrderedDict(
                                ResourceId=kinesis_streams_name.get('StreamNames'),
                                ResourceName=kinesis_streams_name.get('StreamNames'),
                                ResourceType='Kinesis_Stream',
                                Region=region))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_ecs_task_definition_root(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ecs_task_definition = run_aws_operation(
                        credentials,
                        'ecs',
                        'list_task_definitions',
                        region_name=region,
                        response_key='taskDefinitionArns')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for task in ecs_task_definition:
                    evaluated_resources += 1
                    task_info = run_aws_operation(
                        credentials,
                        'ecs',
                        'describe_task_definition',
                        operation_args={
                            'taskDefinition': task},
                        region_name=region)
                    for container_info in task_info.get('taskDefinition', {}).get('containerDefinitions', []):
                        if 'readonlyRootFilesystem' not in container_info or not container_info[
                            'readonlyRootFilesystem']:
                            output.append(
                                OrderedDict(
                                    ResourceId=task,
                                    ResourceName=container_info.get('name', ''),
                                    Resource='Tasks',
                                    Region=region))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_ecs_task_definition_privileges_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ecs_task_definition = run_aws_operation(
                        credentials,
                        'ecs',
                        'list_task_definitions',
                        region_name=region,
                        response_key='taskDefinitionArns')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for tasks in ecs_task_definition:
                    evaluated_resources += 1
                    task_info = run_aws_operation(
                        credentials,
                        'ecs',
                        'describe_task_definition',
                        operation_args={
                            'taskDefinition': tasks},
                        region_name=region)
                    for container_info in task_info.get('taskDefinition', {}).get('containerDefinitions', []):
                        if container_info.get('privileged'):
                            output.append(
                                OrderedDict(
                                    ResourceId=tasks,
                                    ResourceName=tasks,
                                    ResourceType='Tasks'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def find_log4j_vulnerability(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args["service_account_id"]
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            results = db['security_findings'].find({
                'service_account_id': ObjectId(service_account_id),
                'service_name': self.execution_args['service_name'],
                'status': 'active', 'security_id': self.execution_args['args'].get('CVE_ID')})
            for result in results:
                output_response = OrderedDict(
                    ResourceId=result.get('resource_id'),
                    ResourceName=result.get("resource_name"),
                    ResourceType=result.get("resource_type"),
                    ServiceAccountName=result.get('service_account_name')
                )
                output.append(output_response)
                evaluated_resources += 1
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_bucket_data_ingestion(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            service_account_id = self.execution_args["service_account_id"]
            data_size = self.execution_args['args'].get("data_size_in_GB")
            time_interval = self.execution_args['args'].get("time_interval_in_minutes")
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            query = [{"$match": {"metric_name": "storage.googleapis.com/network/received_bytes_count",
                                 "resource_type": "Bucket", "alert_type": "monitoring",
                                 "service_account_id": service_account_id,
                                 "event_creation_time": {"$lte": datetime.utcnow(),
                                                         "$gt": datetime.utcnow() - timedelta(minutes=time_interval)}}},
                     {"$group": {"_id": "$resourceId", "GB": {"$sum": {"$divide": ["$metric_value", 1048576]}}}}]
            results = list(db.cloudops_event_logger.aggregate(query, cursor={}))
            for result in results:
                if result.get("GB") > data_size:
                    resource_id = result["_id"]
                    evaluated_resources += 1
                    response = {"ResourceId": resource_id,
                                "ResourceName": resource_id,
                                "ResourceType": "Bucket",
                                "Resource": "Buckets"
                                }
                    output.append(response)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_resource_provision(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            service_account_id = self.execution_args["service_account_id"]
            number_of_resources = self.execution_args['args'].get("number_of_resources")
            time_interval = self.execution_args['args'].get("time_interval_in_minutes")
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            query = [{"$match": {"operation_type": "insert",
                                 "alert_type": "activity_log",
                                 "service_account_id": service_account_id,
                                 "event_creation_time": {"$lte": datetime.utcnow(),
                                                         "$gt": datetime.utcnow() - timedelta(minutes=time_interval)}}},
                     {"$project": {"resourceId": 1, "resource_type": 1}}]
            results = list(db.cloudops_event_logger.aggregate(query, cursor={}))
            if len(results) > number_of_resources:
                for result in results:
                    evaluated_resources += 1
                    response = {"ResourceId": result.get("resourceId"),
                                "ResourceName": result.get("resourceId"),
                                "Resource": result.get("resource"),
                                "ResourceType": result.get("resource_type")
                                }
                    output.append(response)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_resource_modification(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            service_account_id = self.execution_args["service_account_id"]
            number_of_resources = self.execution_args['args'].get("number_of_resources")
            time_interval = self.execution_args['args'].get("time_interval_in_minutes")
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            query = [{"$match": {"operation_type": {"$in": ["patch", "update"]},
                                 "alert_type": "activity_log",
                                 "service_account_id": service_account_id,
                                 "event_creation_time": {"$lte": datetime.utcnow(),
                                                         "$gt": datetime.utcnow() - timedelta(minutes=time_interval)}}},
                     {"$project": {"resourceId": 1, "resource_type": 1}}]
            results = list(db.cloudops_event_logger.aggregate(query, cursor={}))
            if len(results) > number_of_resources:
                for result in results:
                    evaluated_resources += 1
                    response = {"ResourceId": result.get("resourceId"),
                                "ResourceName": result.get("resourceId"),
                                "Resource": result.get("resource"),
                                "ResourceType": result.get("resource_type")
                                }
                    output.append(response)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_frequent_autoscaling(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            service_account_id = self.execution_args["service_account_id"]
            number_of_resources = self.execution_args['args'].get("number_of_times")
            time_interval = self.execution_args['args'].get("time_interval_in_minutes")
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            query = [{"$match": {"operation_type": "compute.instanceGroupManagers.insert",
                                 "alert_type": "activity_log",
                                 "service_account_id": service_account_id,
                                 "event_creation_time": {"$lte": datetime.utcnow(),
                                                         "$gt": datetime.utcnow() - timedelta(minutes=time_interval)}}},
                     {"$project": {"resourceId": 1, "resource_type": 1,
                                   "resource_name": 1}}]
            results = list(db.cloudops_event_logger.aggregate(query, cursor={}))
            if len(results) > number_of_resources:
                for result in results:
                    evaluated_resources += 1
                    response = {"ResourceId": result.get("resourceId"),
                                "ResourceName": result.get("resource_name"),
                                "Resource": result.get("resource"),
                                "ResourceType": result.get("resource_type")
                                }
                    output.append(response)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_redshift_clusters_not_publicly_accessible(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    redshift_clusters = run_aws_operation(
                        credentials, 'redshift', 'describe_clusters', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for cluster_info in redshift_clusters.get('Clusters'):
                    evaluated_resources.append(
                        cluster_info.get('ClusterIdentifier'))
                    if not cluster_info.get('PubliclyAccessible'):
                        output.append(
                            OrderedDict(
                                ResourceId=cluster_info.get('ClusterIdentifier'),
                                ResourceName=cluster_info.get('ClusterIdentifier'),
                                Resource='Redshift',
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_security_group_overly_permissive_to_all_traffic(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region,
                        response_key='SecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for security_group in security_groups:
                    evaluated_resources += 1
                    for inbound_traffic in security_group.get('IpPermissions'):
                        for inbound_cidr in inbound_traffic.get('IpRanges'):
                            cidr_ip4_range = inbound_cidr.get('CidrIp')[-2:]
                            '''
                                Subnet CidrIp mask  192.0. 2.0/24, 0.0.0.0/0, 0.0.0.31, 0.0.0.26 
                                ingress route protocol -1 have CidrIp': '0.0.0.0/0' is default and not 
                                recommended for SG. Violate if CIDR notation contains less than or eq 28 bits
                            '''
                            try:
                                if int(cidr_ip4_range) <= 28:
                                    output.append(OrderedDict(
                                        ResourceId=security_group.get('GroupId'),
                                        ResourceName=security_group.get('GroupId'),
                                        Resource='Security_Groups'))
                            except ValueError:
                                output.append(OrderedDict(
                                    ResourceId=security_group.get('GroupId'),
                                    ResourceName=security_group.get('GroupId'),
                                    Resource='Security_Groups'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cloud_front_protocol_policy_does_not_enforce_https_only(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            cloud_front_response = run_aws_operation(
                credentials, 'cloudfront', 'list_distributions')
            operation_args = {}
            for cloud_front_info in cloud_front_response.get('DistributionList', {}).get('Items'):
                operation_args.update(Id=cloud_front_info.get('Id'))
                evaluated_resources.append(cloud_front_info.get('Id'))
                cloud_front_distribution = run_aws_operation(
                    credentials, 'cloudfront', 'get_distribution', operation_args)
                if cloud_front_distribution.get('Distribution', {}).get('DistributionConfig', {}).get(
                        'DefaultCacheBehavior', {}).get('ViewerProtocolPolicy') == "allow-all":
                    output.append(
                        OrderedDict(
                            ResourceId=cloud_front_info['Id'],
                            ResourceName=cloud_front_info['Id'],
                            Resource='Stack',
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name']))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def aws_cloudtrail_bucket_publicly_accessible(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    cloudtrail_client = run_aws_operation(
                        credentials, 'cloudtrail', 'describe_trails', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                trail_list = cloudtrail_client['trailList']
                operation_args = {}
                for s3_bucket in trail_list:
                    operation_args.update(Bucket=s3_bucket.get('Name'))
                    evaluated_resources += 1
                    try:
                        s3_get_bucket_policy_status = run_aws_operation(
                            credentials, 's3', 'get_bucket_policy_status', operation_args)
                        s3_access = s3_get_bucket_policy_status.get('PolicyStatus')
                        if s3_access.get('IsPublic'):
                            output.append(
                                OrderedDict(
                                    ResourceId=s3_bucket.get('Name'),
                                    ResourceName=s3_bucket.get('Name'),
                                    ResourceType='Cloudtrail'))

                    except Exception as e:
                        if '(NoSuchPublicAccessBlockConfiguration)' in str(e) or '(NoSuchBucket)' in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=s3_bucket.get('Name'),
                                    ResourceName=s3_bucket.get('Name'),
                                    ResourceType='Cloudtrail'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_has_expired_ssl_tls_certificates(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            certificate_list = run_aws_operation(
                credentials, 'iam', 'list_server_certificates', response_key='ServerCertificateMetadataList')
            for certificates in certificate_list:
                evaluated_resources += 1
                ssl_expiration_date = certificates.get('Expiration', '').replace(tzinfo=None)
                if (ssl_expiration_date - datetime.now()).days <= 0:
                    output.append(OrderedDict(
                        ResourceId=certificates['ServerCertificateId'],
                        ResourceName=certificates['ServerCertificateName'],
                        ResourceType="IAM"
                    ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_public_ip_associated_with_sg_have_internet_access(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    instance_dict = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region).get('Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                operation_args = {}
                for reservation in instance_dict:
                    for instance in reservation.get('Instances'):
                        for sg in instance.get('SecurityGroups'):
                            operation_args.update(GroupIds=[sg.get('GroupId')])
                            security_groups = run_aws_operation(
                                credentials, 'ec2', 'describe_security_groups', operation_args, region_name=region)
                            for security_group in security_groups.get('SecurityGroups'):
                                evaluated_resources.append(sg.get('GroupId'))
                                for outbound in security_group.get('IpPermissionsEgress'):
                                    for outbound_cidr in outbound.get('IpRanges'):
                                        # outbound traffic 0.0.0.0/0 allows public access to security groups
                                        # source can be any ip address, means from any system request is accepted
                                        if outbound_cidr.get('CidrIp') == '0.0.0.0/0':
                                            output.append(
                                                OrderedDict(
                                                    ResourceId=sg.get('GroupId'),
                                                    ResourceName=sg.get('GroupId'),
                                                    Resource='EC2'))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def aws_network_acls_with_inbound_rule_allow_all_traffic(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    network_response = run_aws_operation(
                        credentials, 'ec2', 'describe_network_acls', region_name=region, response_key='NetworkAcls')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for network_acl in network_response:
                    if not network_acl.get('Associations', []):
                        continue
                    evaluated_resources += 1
                    if any(
                            [True if (x.get('RuleAction') == 'allow') and
                                     (x.get('Protocol') == '-1') and
                                     (x.get('Egress') is False) and
                                     (
                                             (x.get('Ipv6CidrBlock') == '::/0') or
                                             (x.get('CidrBlock') == '0.0.0.0/0')
                                     )
                             else False
                             for x in network_acl.get('Entries', [])]):
                        output.append(
                            OrderedDict(
                                ResourceId=network_acl.get('NetworkAclId'),
                                ResourceName=network_acl.get('NetworkAclId'),
                                ResourceType='Instances'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_encrypted_sns_topic(self, **kwargs):
        output = list()
        topiclist = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    topic = run_aws_operation(credentials, 'sns', 'list_topics', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                if topic:
                    temp = topic.get("Topics", [])
                    topic_list = [x.get("TopicArn", "") for x in temp]
                    for topics in topic_list:
                        topicarn = {'TopicArn': topics}
                        response = run_aws_operation(credentials, 'sns', 'get_topic_attributes',
                                                     operation_args=topicarn, region_name=region)
                        if "KmsMasterKeyId" in response['Attributes']:
                            evaluated_resources += 1
                            if response['Attributes']['KmsMasterKeyId'] != "alias/aws/sns":
                                rid = response["TopicArn"]
                                if rid not in topiclist:
                                    topiclist.append(rid)
                                    output.append(
                                        OrderedDict(ResourceId=response['Attributes'].get("TopicArn", "NA"),
                                                    ResourceName=response['Attributes'].get("DisplayName", "NA"),
                                                    Resource="SNS",
                                                    ServiceAccountId=service_account_id,
                                                    ServiceAccountName=self.execution_args['service_account_name']))
                        else:
                            output.append(
                                OrderedDict(ResourceId=response['Attributes'].get("TopicArn", "NA"),
                                            ResourceName=response['Attributes'].get("DisplayName", "NA"),
                                            Resource="SNS",
                                            ServiceAccountId=service_account_id,
                                            ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_sns_topic_exposed(self, **kwargs):
        output = list()
        topiclist = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    topic = run_aws_operation(credentials, 'sns', 'list_topics', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                if topic:
                    temp = topic.get("Topics", [])
                    topic_list = [x.get("TopicArn", "") for x in temp]
                    for topics in topic_list:
                        topic_arn = {'TopicArn': topics}
                        response = run_aws_operation(credentials, 'sns', 'get_topic_attributes',
                                                     operation_args=topic_arn, region_name=region)
                        if 'Policy' in response['Attributes']:
                            response_attributes = response['Attributes']['Policy']
                            statement_value = json.loads(response_attributes)
                            statement = statement_value.get('Statement', "")
                            for value in statement:
                                if "AWS" in value['Principal']:
                                    evaluated_resources += 1
                                    if value['Principal']['AWS'] != "*":
                                        if topics not in topiclist:
                                            topiclist.append(topics)
                                            output.append(
                                                OrderedDict(ResourceId=response['Attributes'].get("TopicArn", "NA"),
                                                            ResourceName=response['Attributes'].get("DisplayName",
                                                                                                    "NA"),
                                                            ResourceType="SNS"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_rds_transport_encryption(self, **kwargs):
        output = list()
        resourceidlist = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    response = run_aws_operation(credentials, 'rds', 'describe_db_instances', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                dbinstances = response["DBInstances"]
                for each_instance in dbinstances:
                    dbparametergroup = each_instance["DBParameterGroups"]
                    for dbparameter_group_name in dbparametergroup:
                        dbpname = dbparameter_group_name["DBParameterGroupName"]
                        param = {'DBParameterGroupName': dbpname}
                        db_parameter = run_aws_operation(credentials, 'rds', 'describe_db_parameters',
                                                         operation_args=param, region_name=region)
                        for each_parameter in db_parameter["Parameters"]:
                            evaluated_resources += 1
                            if each_parameter["ParameterName"] == "rds.force_ssl":
                                if each_parameter["ParameterValue"] != "1":
                                    dbresid = each_instance["DbiResourceId"]
                                    if dbresid not in resourceidlist:
                                        resourceidlist.append(dbresid)
                                        output.append(
                                            OrderedDict(ResourceId=each_instance.get("DbiResourceId", "NA"),
                                                        ResourceName=each_instance.get("DBInstanceIdentifier", "NA"),
                                                        Resource="RDS",
                                                        ServiceAccountId=service_account_id,
                                                        ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_network_acls_with_outbound_rule_allow_all_traffic(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    network_response = run_aws_operation(
                        credentials, 'ec2', 'describe_network_acls', region_name=region, response_key='NetworkAcls')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for network_acl in network_response:
                    if not network_acl.get('Associations', []):
                        continue
                    evaluated_resources += 1
                    if any(
                            [True if (x.get('RuleAction') == 'allow') and
                                     (x.get('Protocol') == '-1') and
                                     (x.get('Egress') is True) and
                                     (
                                             (x.get('Ipv6CidrBlock') == '::/0') or
                                             (x.get('CidrBlock') == '0.0.0.0/0')
                                     )
                             else False
                             for x in network_acl.get('Entries', [])]):
                        output.append(
                            OrderedDict(
                                ResourceId=network_acl.get('NetworkAclId'),
                                ResourceName=network_acl.get('NetworkAclId'),
                                ResourceType='Instances'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_instance_not_in_private_subnet(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_client = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for db_instance in rds_client:
                    subnets = [
                        subnet.get('SubnetIdentifier') for subnet in db_instance.get("DBSubnetGroup", {}).get("Subnets")
                        if subnet.get('SubnetIdentifier')
                    ]
                    route_tables = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_route_tables',
                        operation_args={
                            "Filters": [{
                                'Name': 'association.subnet-id',
                                'Values': subnets
                            }]},
                        response_key='RouteTables',
                        region_name=region)
                    for route_table in route_tables:
                        evaluated_resources += 1
                        for each_route in route_table.get("Routes"):
                            if 'igw-' in each_route.get("GatewayId", '') and \
                                    "0.0.0.0/0" in each_route.get("DestinationCidrBlock"):
                                output.append(
                                    OrderedDict(
                                        ResourceId=db_instance.get("DBInstanceIdentifier"),
                                        ResourceName=db_instance.get("DBInstanceIdentifier"),
                                        GatewayId=each_route.get('GatewayId'),
                                        ResourceType="RDS",
                                        Region=region))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_redshift_does_not_have_required_ssl_configuration(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    cluster_info = run_aws_operation(
                        credentials, 'redshift', 'describe_clusters', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                operation_args = {}
                for cluster_name in cluster_info.get('Clusters'):
                    operation_args.update(
                        ParameterGroupName=cluster_name.get('ClusterParameterGroups', {}).get('ParameterGroupName'))
                    evaluated_resources.append(
                        cluster_info.get('ClusterIdentifier'))
                    cluster_response = run_aws_operation(
                        credentials, 'redshift', 'describe_cluster_parameters', operation_args, region_name=region)
                    for parameter_info in cluster_response.get('Parameters'):
                        if parameter_info.get('ParameterName') == "require_ssl" and parameter_info.get(
                                'ParameterValue') == "false":
                            output.append(
                                OrderedDict(
                                    ResourceId=cluster_info.get('ClusterIdentifier'),
                                    ResourceName=cluster_info.get('ClusterIdentifier'),
                                    Resource='Cluster',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_buckets_not_configured_with_secure_data_transport_policy(self):
        output = list()
        evaluated_resources = list()
        try:
            credentials = self.execution_args['auth_values']
            service_account_id = self.execution_args.get("service_account_id")
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_client = run_aws_operation(credentials, 'kms', 'list_aliases', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                default_key = ""
                for each_kms in kms_client.get('Aliases'):
                    if each_kms.get('AliasName').split(':')[0] == 'alias/aws/s3':
                        default_key = each_kms.get('AliasArn')
                s3_buckets = run_aws_operation(
                    credentials, 's3', 'list_buckets')
                operation_args = {}
                for s3_bucket in s3_buckets.get('Buckets'):
                    try:
                        operation_args.update(Bucket=s3_bucket.get('Name'))
                        evaluated_resources.append(s3_bucket.get('Name'))
                        s3_bucket_value = run_aws_operation(
                            credentials, 's3', 'get_bucket_encryption', operation_args)
                        s3_bucket_encryption = s3_bucket_value.get('ServerSideEncryptionConfiguration').get('Rules')
                        for s3_encryption_rules in s3_bucket_encryption:
                            if s3_encryption_rules.get('ApplyServerSideEncryptionByDefault', {}).get(
                                    'SSEAlgorithm') == 'AES256':
                                output.append(
                                    OrderedDict(
                                        ResourceId=s3_bucket.get('Name'),
                                        ResourceName=s3_bucket.get('Name'),
                                        Resource="Buckets",
                                        ServiceAccountId=service_account_id,
                                        ServiceAccountName=self.execution_args['service_account_name']))
                            elif s3_encryption_rules.get('ApplyServerSideEncryptionByDefault', {}).get(
                                    'SSEAlgorithm') == 'aws:kms':
                                if s3_encryption_rules.get('ApplyServerSideEncryptionByDefault', {}).get(
                                        'KMSMasterKeyID') == default_key:
                                    output.append(
                                        OrderedDict(
                                            ResourceId=s3_bucket.get('Name'),
                                            ResourceName=s3_bucket.get('Name'),
                                            Resource="Buckets",
                                            ServiceAccountId=service_account_id,
                                            ServiceAccountName=self.execution_args['service_account_name']))
                    except Exception as e:
                        if '(ServerSideEncryptionConfigurationNotFoundError)' in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=s3_bucket.get('Name'),
                                    ResourceName=s3_bucket.get('Name'),
                                    Resource="Buckets",
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_buckets_are_accessible_to_any_authenticated_user(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            operation_args = {}
            for s3_bucket in s3_buckets.get('Buckets'):
                operation_args.update(Bucket=s3_bucket.get('Name'))
                s3_bucket_acl = run_aws_operation(
                    credentials, 's3', 'get_bucket_acl', operation_args)
                for s3_bucket_acl_grant in s3_bucket_acl.get('Grants'):
                    if s3_bucket_acl_grant.get('Grantee', {}).get(
                            'URI') == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                        output.append(
                            OrderedDict(
                                ResourceId=s3_bucket['Name'],
                                ResourceName=s3_bucket['Name'],
                                ResourceType='S3'))
                        evaluated_resources += 1
            output = [dict(t) for t in {tuple(d.items()) for d in output}]  # remove duplicates from `output` list
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_logging_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(
                credentials, 's3', 'list_buckets')
            operation_args = {}
            for bucket in s3_buckets.get('Buckets'):
                operation_args.update(Bucket=bucket.get('Name'))
                evaluated_resources += 1
                s3_bucket_checking = run_aws_operation(
                    credentials, 's3', 'get_bucket_logging', operation_args)
                if s3_bucket_checking.get('LoggingEnabled'):
                    output.append(
                        OrderedDict(
                            ResourceId=bucket.get('Name'),
                            ResourceName=bucket.get('Name'),
                            ResourceType='S3'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_group_has_users_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            group_response = run_aws_operation(
                credentials, 'iam', 'list_groups', response_key='Groups')
            for group in group_response:
                evaluated_resources += 1
                operation_args = dict(GroupName=group.get('GroupName', 'NA'))
                group_info = run_aws_operation(
                    credentials, 'iam', 'get_group', operation_args)
                if not group_info.get('Users'):
                    output.append(
                        OrderedDict(
                            ResourceId=group.get('GroupName'),
                            ResourceName=group.get('GroupName'),
                            ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_unused_credential_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for iam in iam_response:
                evaluated_resources += 1
                operation_args = dict(UserName=iam.get('UserName', 'NA'))
                iam_user_response = run_aws_operation(
                    credentials, 'iam', 'list_access_keys', operation_args)
                for access_key_usage in iam_user_response.get('AccessKeyMetadata', []):
                    if access_key_usage.get('Status') == 'Inactive':
                        output.append(
                            OrderedDict(
                                ResourceId=iam.get('UserName'),
                                ResourceName=iam.get('UserName'),
                                ResourceType='iam'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_custom_security_policy_ssl_check(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region)
                    default_policy_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancer_policies',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                default_policy_list = [elb_name.get('PolicyName')
                                       for elb_name in default_policy_response.get('PolicyDescriptions')]
                for elb in elb_response.get('LoadBalancerDescriptions'):
                    evaluated_resources.append(elb.get('LoadBalancerName'))
                    for policy_name in elb.get('ListenerDescriptions'):
                        if policy_name.get('Listener', {}).get('Protocol') == 'HTTPS':
                            if policy_name.get('PolicyNames') in default_policy_list:
                                output.append(
                                    OrderedDict(
                                        ResourceId=elb.get('LoadBalancerName'),
                                        ResourceName=elb.get('LoadBalancerName'),
                                        Resource="ELB",
                                        ServiceAccountId=service_account_id,
                                        ServiceAccountName=self.execution_args['service_account_name']))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_instances_with_blacklisted_instance_types(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            blocklisted_instance_type = list(
                map(str.strip, self.execution_args['args']['blocklisted_instance_type'].split(',')))
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                operation_args = {"Filters": [
                    {
                        'Name': 'instance-state-name',
                        'Values': [
                            "running"
                        ]
                    },
                    {
                        'Name': 'instance-type',
                        'Values': blocklisted_instance_type,
                    },
                ]}
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation['Instances']:
                        evaluated_resources += 1
                        output.append(
                            OrderedDict(
                                ResourceId=instance['InstanceId'],
                                ResourceName=instance['InstanceId'],
                                Resource='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_policy_no_statements_with_admin_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args1 = {}
        try:
            credentials = self.execution_args['auth_values']
            response_iterator = run_aws_operation(
                credentials, 'iam', 'list_policies',
                operation_args={
                    'Scope': 'Local'},
                response_key='Policies')
            for policies in response_iterator:
                evaluated_resources += 1
                operation_args1.update(
                    PolicyArn=policies.get('Arn', 'NA'),
                    VersionId=policies.get('DefaultVersionId', 'NA'))
                policy_response = run_aws_operation(
                    credentials, 'iam', 'get_policy_version', operation_args=operation_args1)
                response = policy_response.get('PolicyVersion', {}).get('Document', {})
                for i in response.get('Statement', []):
                    if i and isinstance(i, dict):
                        if i.get('Effect') == "Allow" and i.get('Action') == "*" and i.get('Resource') == "*":
                            output.append(
                                OrderedDict(
                                    ResourceId=policies.get('Arn', 'NA'),
                                    ResourceName=policies.get('Arn', 'NA'),
                                    ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_user_no_policies_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            user_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for user in user_response:
                evaluated_resources += 1
                operation_args = dict(UserName=user.get('UserName', 'NA'))
                user_policy = run_aws_operation(
                    credentials, 'iam', 'list_user_policies', operation_args)
                if user_policy.get('PolicyNames'):
                    output.append(
                        OrderedDict(
                            ResourceId=user.get('UserName'),
                            ResourceName=user.get('UserName'),
                            ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_volume_inuse_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    volume_response = run_aws_operation(
                        credentials, 'ec2', 'describe_volumes', region_name=region)
                    for response in volume_response.get('Volumes'):
                        evaluated_resources += 1
                        operation_args.update(VolumeIds=[response.get('VolumeId')])
                        ebs_volumes_info = run_aws_operation(
                            credentials,
                            'ec2',
                            'describe_volumes',
                            response_key='Volumes',
                            operation_args=operation_args,
                            region_name=region)
                        for ebs_volume_info in ebs_volumes_info:
                            if ebs_volume_info.get('State') == 'available':
                                output.append(
                                    OrderedDict(
                                        ResourceId=response.get('VolumeId'),
                                        ResourceName=response.get('VolumeId'),
                                        ResourceType='Volumes'))
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_instances_detailed_monitoring_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    instance_dict = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region).get('Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for reservation in instance_dict:
                    for instance in reservation.get('Instances'):
                        evaluated_resources += 1
                        if instance.get('Monitoring', {}).get('State') != 'enabled':
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('InstanceId'),
                                    ResourceName=instance.get('InstanceId'),
                                    ResourceType='Instances'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_approved_amis_by_tags(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            approved_ami = self.execution_args['args'].get('ami_tag')
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    instance_dict = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region).get('Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for reservation in instance_dict:
                    evaluated_resources += 1
                    for instance in reservation.get('Instances'):
                        if approved_ami not in instance.get('ImageId'):
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('InstanceId'),
                                    ResourceName=instance.get('InstanceId'),
                                    ResourceType='Instances'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_access_key_rotated(self, **kwargs):
        output = list()
        evaluated_resources = 0
        today = datetime.utcnow().replace(tzinfo=None)
        try:
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for iam in iam_response:
                evaluated_resources += 1
                operation_args = dict(UserName=iam.get('UserName', 'NA'))
                iam_user_response = run_aws_operation(
                    credentials, 'iam', 'list_access_keys', operation_args, response_key='AccessKeyMetadata')
                for access_key_usage in iam_user_response:
                    if (today - access_key_usage.get('CreateDate', today).replace(tzinfo=None)).days > 30:
                        output.append(
                            OrderedDict(
                                ResourceId=iam.get('UserName'),
                                ResourceName=iam.get('UserName'),
                                ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_encrypted_volumes(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ebs_volumes_response = run_aws_operation(
                        credentials, 'ec2', 'describe_volumes', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                ebs_volume_list = ebs_volumes_response.get('Volumes')
                for ebs_Volume in ebs_volume_list:
                    evaluated_resources.append(ebs_Volume.get('VolumeId'))
                    if not ebs_Volume.get('Encrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=ebs_Volume.get('VolumeId'),
                                ResourceName=ebs_Volume.get('VolumeId'),
                                Resource='Volumes',
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def aws_root_account_mfa_enabled(self, **kwargs):
        output, evaluated_resources = self.iam_root_access('mfa_active')
        return output, evaluated_resources

    def aws_approved_amis_by_id(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            approved_ami = self.execution_args['args'].get('ami_id')
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    instance_dict = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region).get('Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for reservation in instance_dict:
                    evaluated_resources.append(reservation.get('Instances'))
                    for instance in reservation.get('Instances'):
                        if approved_ami not in instance.get('ImageId'):
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('InstanceId'),
                                    ResourceName=instance.get('InstanceId'),
                                    Resource='Instances',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))
            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_versioning_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            list_s3_buckets = run_aws_operation(
                credentials, 's3', 'list_buckets')
            for bucket in list_s3_buckets.get('Buckets'):
                operation_args = dict(Bucket=bucket.get('Name'))
                evaluated_resources += 1
                s3_bucket_versioning = run_aws_operation(
                    credentials, 's3', 'get_bucket_versioning', operation_args)
                if s3_bucket_versioning.get('Status') != 'Enabled':
                    output.append(
                        OrderedDict(
                            ResourceId=bucket.get('Name'),
                            ResourceName=bucket.get('Name'),
                            ResourceType='S3'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_serverside_encryption_enabled(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(
                credentials, 's3', 'list_buckets')
            operation_args = {}
            for s3_bucket in s3_buckets.get('Buckets'):
                try:
                    operation_args.update(Bucket=s3_bucket.get('Name'))
                    evaluated_resources += 1
                    _ = run_aws_operation(
                        credentials, 's3', 'get_bucket_encryption', operation_args)
                except Exception as e:
                    if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                        output.append(
                            OrderedDict(
                                ResourceId=s3_bucket.get('Name'),
                                ResourceName=s3_bucket.get('Name'),
                                ResourceType="S3"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_instances_managed_by_ssm(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region).get('Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation.get('Instances'):
                        evaluated_resources += 1
                        operation_args = {"InstanceInformationFilterList": [
                            {
                                'key': 'InstanceIds',
                                'valueSet': [
                                    instance['InstanceId'],
                                ]
                            },
                        ]}
                        try:
                            ssm_response = run_aws_operation(
                                credentials,
                                'ssm',
                                'describe_instance_information',
                                operation_args=operation_args,
                                region_name=region)
                        except Exception as e:
                            raise Exception(
                                'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                                    str(e)))
                        if not ssm_response.get('InstanceInformationList'):
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('InstanceId'),
                                    ResourceName=instance.get('InstanceId'),
                                    ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_acm_cert_validity(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            operation_args.update(CertificateStatuses=['EXPIRED'])
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    acm_certificates = run_aws_operation(credentials, 'acm', 'list_certificates',
                                                         operation_args,
                                                         region_name=region,
                                                         response_key='CertificateSummaryList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for acm in acm_certificates:
                    evaluated_resources += 1
                    output.append(OrderedDict(
                        ResourceId=acm.get('CertificateArn').split('/')[1],
                        ResourceName=acm.get('CertificateArn').split('/')[1],
                        ResourceType='Certificate_Manager',
                        DomainName=acm.get('DomainName')
                    ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_ecr_repository_exposed(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    response = run_aws_operation(credentials, 'ecr', 'describe_repositories', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                repositories = response['repositories']
                for name in repositories:
                    evaluated_resources += 1
                    name_args = name['repositoryName']
                    repository_arn = name['repositoryArn']
                    repository_name_args = {'repositoryName': name_args}
                    try:
                        policy_response = run_aws_operation(credentials, 'ecr', 'get_repository_policy',
                                                            region_name=region, operation_args=repository_name_args)
                        if policy_response:
                            policy_text = policy_response['policyText']
                            policy_value = json.loads(policy_text)
                            statement = policy_value.get('Statement')
                            if statement['Effect'] == 'Allow' and statement['Principal'] == "*":
                                output.append(
                                    OrderedDict(ResourceId=repository_arn,
                                                ResourceName=name_args,
                                                ResourceType="Repository_private",
                                                Region=region))
                    except Exception as e:
                        if '(RepositoryPolicyNotFoundException)' in str(e):
                            output.append(
                                OrderedDict(ResourceId=repository_arn,
                                            ResourceName=name_args,
                                            ResourceType="Repository_private",
                                            Region=region))
                            continue
                        else:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_mfa_enabled_for_iam_console_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            user_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for user in user_response:
                evaluated_resources += 1
                operation_args = dict(UserName=user.get('UserName', 'NA'))
                mfa_response = run_aws_operation(
                    credentials, 'iam', 'list_mfa_devices', operation_args, response_key='MFADevices')
                if not mfa_response:
                    output.append(
                        OrderedDict(
                            ResourceId=user.get('UserName'),
                            ResourceName=user.get('UserName'),
                            ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_instances_in_vpc(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region).get('Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation.get('Instances'):
                        evaluated_resources += 1
                        if instance.get('VpcId'):
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('VpcId'),
                                    ResourceName=instance.get('VpcId'),
                                    ResourceType='Instances'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_ebs_volumes_attached_stopped_ec2(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            instance_name_dict = {"Filters": [{'Name': 'instance-state-name', 'Values': ['stopped']}]}
            for region in regions:
                try:
                    response = run_aws_operation(credentials, 'ec2', 'describe_instance_status',
                                                 operation_args=instance_name_dict, region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                instance = []
                for instance_status in response['InstanceStatuses']:
                    instance.append(str(instance_status.get('InstanceId')))
                try:
                    response_list = run_aws_operation(credentials, 'ec2', 'describe_volumes', region_name=region,
                                                      response_key='Volumes')
                except Exception as e:
                    raise Exception(str(e))
                for volume in response_list:
                    evaluated_resources += 1
                    attachments = volume['Attachments']
                    for instance_id_list in attachments:
                        instance_id = str(instance_id_list.get('InstanceId'))
                        if instance_id in instance:
                            output.append(
                                OrderedDict(ResourceId=volume['VolumeId'],
                                            ResourceName=volume['VolumeId'],
                                            ResourceType="Volumes",
                                            Region=region))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_default_security_group_closed(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    if security_group.get('Description') == 'default VPC security group':
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType='Security_Groups'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_logging_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancers')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerArn=elb['LoadBalancerArn'])
                    elb_log_info = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancer_attributes',
                        operation_args=operation_args,
                        region_name=region)
                    for logging_info in elb_log_info['Attributes']:
                        if logging_info['Key'] == 'access_logs.s3.enabled' and logging_info['Value'] == 'false':
                            output.append(
                                OrderedDict(
                                    ResourceId=elb['LoadBalancerName'],
                                    ResourceName=elb['LoadBalancerName'],
                                    ResourceType="ELB"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_root_account_hardware_mfa_enabled(self, **kwargs):
        output = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get("service_account_name")
            credentials = self.execution_args['auth_values']
            mfa_response = run_aws_operation(
                credentials, 'iam', 'list_virtual_mfa_devices',
                operation_args={
                    'AssignmentStatus': 'Any'},
                response_key='VirtualMFADevices')
            for info in mfa_response:
                if info.get('SerialNumber'):
                    output.append(
                        OrderedDict(
                            ResourceId=info['SerialNumber'],
                            ResourceName=info['SerialNumber'],
                            Resource='iam',
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=service_account_name))
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def check_ebs_not_encrypted_with_cmk(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_list_aliases = run_aws_operation(credentials, 'kms', 'list_aliases', region_name=region)
                except Exception as e:
                    raise Exception(str(e))
                target_key_list = []
                for kms_list_alias in kms_list_aliases['Aliases']:
                    if kms_list_alias['AliasName'] == 'alias/aws/ebs':
                        target_key_list.append(str(kms_list_alias.get('TargetKeyId')))
                try:
                    response_list = run_aws_operation(credentials, 'ec2', 'describe_volumes', region_name=region,
                                                      response_key='Volumes')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for response in response_list:
                    evaluated_resources += 1
                    if response['Encrypted']:
                        kms_key_id = response['KmsKeyId']
                        target_id = kms_key_id.split('/')
                        target_key_id = str(target_id[1])
                        if target_key_id in target_key_list:
                            output.append(
                                OrderedDict(ResourceId=response['VolumeId'],
                                            ResourceName=response['VolumeId'],
                                            ResourceType="Volumes",
                                            Region=region))
                    else:
                        output.append(
                            OrderedDict(ResourceId=response['VolumeId'],
                                        ResourceName=response['VolumeId'],
                                        ResourceType="Volumes",
                                        Region=region))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_required_tags(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region).get('Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation.get('Instances'):
                        evaluated_resources += 1
                        if not instance.get('Tags'):
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('InstanceId'),
                                    ResourceName=instance.get('InstanceId'),
                                    ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_snapshots_public_access_prohibited(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_cluster_info = run_aws_operation(
                        credentials, 'rds', 'describe_db_snapshots', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for snapshot in rds_cluster_info.get('DBSnapshots'):
                    operation_args = dict(snapshot=snapshot.get('DBSnapshotIdentifier'))
                    evaluated_resources += 1
                    try:
                        snapshot_check = run_aws_operation(
                            credentials,
                            'rds',
                            'describe_db_snapshot_attributes',
                            operation_args=operation_args,
                            region_name=region)
                    except Exception as e:
                        raise Exception(
                            'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                                str(e)))
                    for value in snapshot_check.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', {}):
                        if value.get('AttributeValues'):
                            output.append(
                                OrderedDict(
                                    ResourceId=snapshot.get('DBSnapshotIdentifier'),
                                    ResourceName=snapshot.get('DBSnapshotIdentifier'),
                                    Resource='RDS',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_public_read_access_prohibited(self, *kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            for s3_bucket in s3_buckets.get('Buckets'):
                operation_args = dict(Bucket=s3_bucket.get('Name'))
                s3_bucket_acl = run_aws_operation(
                    credentials, 's3', 'get_bucket_acl', operation_args)
                for s3_bucket_acl_grant in s3_bucket_acl.get('Grants'):
                    evaluated_resources += 1
                    if s3_bucket_acl_grant.get('Permission') == "READ" and s3_bucket_acl_grant.get(
                            'Grantee', {}).get('URI') == "http://acs.amazonaws.com/groups/global/AllUsers":
                        output.append(
                            OrderedDict(
                                ResourceId=s3_bucket['Name'],
                                Resource=s3_bucket))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_replication_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            sts_client = run_aws_operation(
                credentials, 'sts', 'get_caller_identity')
            bucket_list = run_aws_operation(
                credentials, 's3', 'list_buckets')
            for each_bucket in bucket_list.get('Buckets'):
                evaluated_resources += 1
                operation_args = dict(Bucket=each_bucket.get('Name'))
                try:
                    bucket_policy = run_aws_operation(
                        credentials, 's3', 'get_bucket_policy', operation_args)
                except Exception as e:
                    if 'NoSuchBucketPolicy' in str(e):
                        continue
                    else:
                        raise Exception(str(e))
                policy = bucket_policy.get('Policy')
                policy = json.loads(policy)
                for statement in policy.get('Statement'):
                    if statement and isinstance(statement, dict) and 'Principal' in statement:
                        if 'AWS' in statement.get('Principal'):
                            try:
                                aws_account_id = statement.get('Principal', {}).get('AWS').split(':')[-2]
                            except IndexError:
                                continue
                            if aws_account_id != sts_client.get('Account'):
                                output.append(OrderedDict(
                                    ResourceId=each_bucket.get('Name'),
                                    ResourceName=each_bucket.get('Name'),
                                    ResourceType='Buckets'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_restricted_ssh(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_permission in security_group.get('IpPermissions'):
                        all_conditional = [
                            True if security_group_permission.get('IpProtocol') != '-1' else False,
                            True if security_group_permission.get('FromPort') == 22 else False,
                            True if security_group_permission.get('ToPort') == 22 else False
                        ]
                        if all(all_conditional):
                            for ip_address in security_group_permission.get('IpRanges'):
                                security_group_compliant = False if ip_address.get('CidrIp') == '0.0.0.0/0' else True
                            for ip_address in security_group_permission.get('Ipv6Ranges'):
                                security_group_compliant = False if ip_address.get('CidrIp') == '0.0.0.0/0' else True
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                Resource="Security_Groups",
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_blacklisted_actions_prohibited(self):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            operation_args = {}
            owners_id = run_aws_operation(
                credentials, 'sts', 'get_caller_identity').get('Account')
            for bucket in s3_buckets['Buckets']:
                operation_args.update(Bucket=bucket['Name'])
                evaluated_resources += 1
                try:
                    bucket_policy = run_aws_operation(
                        credentials, 's3', 'get_bucket_policy', operation_args)
                    policy = bucket_policy['Policy']
                    policy = json.loads(policy)
                    for statement in policy['Statement']:
                        aws_account_id = statement.get('Principal', {}).get('AWS').split(
                            ':')[-2]
                        if aws_account_id != owners_id:
                            if statement['Effect'] == "Allow" and statement['Action'] == "s3:GetBucket*":
                                output.append(
                                    OrderedDict(
                                        ResourceId=bucket['Name'],
                                        ResourceName=bucket['Name'],
                                        ResourceType="s3"))
                            elif statement['Effect'] == "Allow" and statement['Action'] == "s3:DeleteObject":
                                output.append(
                                    OrderedDict(
                                        ResourceId=bucket['Name'],
                                        ResourceName=bucket['Name'],
                                        ResourceType="s3"))
                except Exception as e:
                    if 'NoSuchBucketPolicy' in str(e):
                        continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_authenticated_users_write_control_access(self):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args.get('auth_values')
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            operation_args = {}
            for s3_bucket in s3_buckets['Buckets']:
                operation_args.update(Bucket=s3_bucket['Name'])
                s3_bucket_acl = run_aws_operation(
                    credentials, 's3', 'get_bucket_acl', operation_args)
                for s3_bucket_acl_grant in s3_bucket_acl['Grants']:
                    evaluated_resources += 1
                    try:
                        if s3_bucket_acl_grant['Permission'] == "WRITE" and s3_bucket_acl_grant[
                            'Grantee']['URI'] == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                            output.append(
                                OrderedDict(
                                    ResourceId=s3_bucket['Name'],
                                    ResourceName=s3_bucket['Name'],
                                    ResourceType='S3'))
                    except KeyError as e:
                        pass
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_users_group_membership_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            user_response = run_aws_operation(
                credentials, 'iam', 'list_users')
            for user in user_response.get('Users'):
                evaluated_resources += 1
                operation_args = dict(UserName=user.get('UserName'))
                group_response = run_aws_operation(
                    credentials, 'iam', 'list_groups_for_user', operation_args)
                if not group_response.get('Groups'):
                    output.append(OrderedDict(
                        ResourceId=user.get('UserName'),
                        ResourceName=user.get('UserName'),
                        Resource='IAM_Users',
                        ServiceAccountId=service_account_id,
                        ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_restricted_common_ports(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            ports = [80, 443, 21, 22, 110, 995, 143, 993, 25, 587, 3306, 53]
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            for port in ports:
                                if security_group_ip_permissions.get('FromPort') == port and \
                                        security_group_ip_permissions.get('ToPort') == port:
                                    for ip_address in security_group_ip_permissions.get('IpRanges'):
                                        if ip_address.get('CidrIp') == '0.0.0.0/0':
                                            security_group_compliant = False
                                    for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                        if ip_address.get('CidrIpv6') == '::/0':
                                            security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                Resource="Security_Groups",
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_root_access_key_check(self, **kwargs):
        output, evaluated_resources = self.iam_root_access('access_key_active')
        return output, evaluated_resources

    def aws_rds_storage_encrypted(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')

                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for db in rds_response:
                    evaluated_resources += 1
                    if not db.get('StorageEncrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=db.get('DBInstanceIdentifier', ''),
                                ResourceName=db.get('DBInstanceIdentifier', ''),
                                ResourceType='RDS'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_dynamodb_table_encryption_enabled(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_response = run_aws_operation(
                        credentials,
                        'dynamodb',
                        'list_tables',
                        region_name=region,
                        response_key='TableNames')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for table in db_response:
                    operation_args.update(TableName=table)
                    evaluated_resources += 1
                    table_response = run_aws_operation(
                        credentials, 'dynamodb', 'describe_table', region_name=region, operation_args=operation_args)
                    try:
                        if table_response.get('SSEDescription', {}).get('Status') in ['DISABLED', 'DISABLING']:
                            output.append(
                                OrderedDict(
                                    ResourceId=table,
                                    ResourceName=table,
                                    ResourceType='Tables'))
                    except Exception as e:
                        if "SSEDescription" in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=table,
                                    ResourceName=table,
                                    ResourceType='Tables'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_vpc_default_security_group_closed(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']

            operation_args.update(Filters=[
                {
                    'Name': 'group-name',
                    'Values': [
                        'default'
                    ]
                },
            ])
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials, 'ec2', 'describe_security_groups',
                        operation_args=operation_args,
                        region_name=region,
                        response_key='SecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups:
                    evaluated_resources += 1
                    security_group_processed = False
                    for in_permission in security_group.get('IpPermissions', []):
                        for ip_address in in_permission.get('IpRanges', []):
                            if security_group_processed:
                                break
                            if ip_address.get('CidrIp') == '0.0.0.0/0':
                                output.append(
                                    OrderedDict(
                                        ResourceId=security_group.get('GroupId', ''),
                                        ResourceName=security_group.get('GroupId', ''),
                                        ResourceType='EC2'))
                        for ipv6_address in in_permission.get('Ipv6Ranges', []):
                            if security_group_processed:
                                break
                            if ipv6_address.get('CidrIpv6') == '::/0':
                                output.append(
                                    OrderedDict(
                                        ResourceId=security_group.get('GroupId', ''),
                                        ResourceName=security_group.get('GroupId', ''),
                                        ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_kms_backing_key_rotation_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_response = run_aws_operation(
                        credentials,
                        'kms',
                        'list_aliases',
                        region_name=region,
                        response_key='Aliases')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for key in kms_response:
                    if 'alias/aws/' not in key.get('AliasName'):
                        operation_args.update(KeyId=key.get('TargetKeyId'))
                        evaluated_resources += 1
                        try:
                            key_info = run_aws_operation(
                                credentials, 'kms', 'get_key_rotation_status',
                                region_name=region,
                                operation_args=operation_args)
                            if not key_info.get('KeyRotationEnabled'):
                                output.append(
                                    OrderedDict(
                                        ResourceId=key.get('TargetKeyId', ''),
                                        ResourceName=key.get('TargetKeyId', ''),
                                        ResourceType='KMS'))
                        except Exception as e:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_lambda_function_public_access_prohibited(self, **kwargs):
        output = list()
        evaluated_resources = 0
        credentials = self.execution_args['auth_values']
        operation_args = {}
        try:
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    operation_args.update(FunctionName=function.get('FunctionName', ''))
                    try:
                        lambda_policy = run_aws_operation(
                            credentials, 'lambda', 'get_policy',
                            region_name=region,
                            operation_args=operation_args)
                        policy = json.loads(lambda_policy['Policy'])
                        for statement in policy.get('Statement', []):
                            if statement.get('Effect') == "Allow" and statement[
                                'Principal'].values() == "*" and not statement.get('Condition'):
                                output.append(
                                    OrderedDict(
                                        ResourceId=function.get('FunctionName', ''),
                                        ResourceName=function.get('FunctionName', ''),
                                        ResourceType='Lambda'))

                            elif "aws" in statement['Principal'] and "*" in statement[
                                'Principal'].values() and not statement.get('Condition'):
                                output.append(
                                    OrderedDict(
                                        ResourceId=function.get('FunctionName', ''),
                                        ResourceName=function.get('FunctionName', ''),
                                        ResourceType='Lambda'))
                    except Exception as e:
                        if "ResourceNotFoundException" in str(e):
                            continue
                        else:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_snapshots_public_prohibited(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_snapshot_info = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_snapshots',
                        region_name=region,
                        response_key='DBSnapshots')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for snapshot in rds_snapshot_info:
                    operation_args.update(DBSnapshotIdentifier=snapshot.get('DBSnapshotIdentifier'))
                    evaluated_resources += 1
                    snapshot_check = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_snapshot_attributes',
                        operation_args=operation_args,
                        region_name=region)
                    for value in snapshot_check.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', []):
                        if 'all' in value.get('AttributeValues', []):
                            output.append(
                                OrderedDict(
                                    ResourceId=snapshot.get('DBSnapshotIdentifier', ''),
                                    ResourceName=snapshot.get('DBSnapshotIdentifier', ''),
                                    ResourceType='RDS'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_shield_advanced_enabled_autorenew(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 1
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                shield_response = {}
                try:
                    shield_response = run_aws_operation(
                        credentials, 'shield', 'describe_subscription', region_name=region)
                except Exception as e:
                    if "ResourceNotFoundException" in str(e):
                        output.append(
                            OrderedDict(
                                ResourceId=shield_response.get('SubscriptionArn',
                                                               self.execution_args['service_account_id']),
                                ResourceName=shield_response.get('SubscriptionArn',
                                                                 self.execution_args['service_account_id']),
                                ResourceType='Shield'))
                if not shield_response.get('Subscription', {}).get('AutoRenew') == 'ENABLED':
                    output.append(
                        OrderedDict(
                            ResourceId=shield_response.get('SubscriptionArn',
                                                           self.execution_args['service_account_id']),
                            ResourceName=shield_response.get('SubscriptionArn',
                                                             self.execution_args['service_account_id']),
                            ResourceType='Shield'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_dynamodb_pitr_enabled(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                db_response = run_aws_operation(credentials, 'dynamodb', 'list_tables', region_name=region,
                                                response_key='TableNames')
                if db_response:
                    for table in db_response:
                        operation_args.update(TableName=table)
                        evaluated_resources += 1
                        try:
                            table_response = run_aws_operation(
                                credentials, 'dynamodb', 'describe_continuous_backups', region_name=region,
                                operation_args=operation_args)
                        except Exception as e:
                            if "TableNotFoundException" in str(e):
                                continue
                            else:
                                raise Exception(str(e))
                        if table_response.get('ContinuousBackupsDescription', {}).get(
                                'PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus') == 'DISABLED':
                            output.append(
                                OrderedDict(
                                    ResourceId=table,
                                    ResourceName=table,
                                    ResourceType='DynamoDB'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_securityhub_enabled(self, **kwargs):
        output = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get("service_account_name")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    _ = run_aws_operation(
                        credentials, 'securityhub', 'describe_hub', region_name=region)

                except Exception as e:
                    if 'not subscribed to AWS Security Hub' in str(e):
                        output.append(
                            OrderedDict(
                                ResourceId=service_account_id,
                                ResourceName=service_account_name,
                                ResourceType='securityhub'))

            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_user_mfa_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(credentials, 'iam', 'list_users', response_key='Users')
            for iam in iam_response:
                evaluated_resources += 1
                operation_args = dict(UserName=iam.get('UserName', 'NA'))
                iam_user_response = run_aws_operation(
                    credentials, 'iam', 'list_mfa_devices', operation_args, response_key='MFADevices')
                if not iam_user_response:
                    output.append(
                        OrderedDict(
                            ResourceId=iam.get('UserName'),
                            ResourceName=iam.get('UserName'),
                            ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_alb_http_to_https_redirection_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    alb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                if alb_response:
                    for alb in alb_response.get('LoadBalancers'):
                        evaluated_resources += 1
                        operation_args = dict(LoadBalancerArn=alb.get('LoadBalancerArn'))
                        listener_info = run_aws_operation(
                            credentials,
                            'elbv2',
                            'describe_load_balancer_attributes',
                            operation_args=operation_args,
                            region_name=region)
                        if listener_info:
                            for listener in listener_info.get('Listeners'):
                                if listener.get('Protocol') == 'HTTP':
                                    if listener:
                                        for redirect in listener.get('DefaultActions'):
                                            if redirect.get('RedirectConfig', {}).get('Protocol') != 'HTTPS':
                                                output.append(
                                                    OrderedDict(
                                                        ResourceId=alb.get('LoadBalancerName'),
                                                        ResourceName=alb.get('LoadBalancerName'),
                                                        ResourceType="ELB"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_instance_no_public_ip(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                instance_dict = ec2_instance_response.get('Reservations')
                for reservation in instance_dict:
                    for instance in reservation.get('Instances'):
                        evaluated_resources += 1
                        if instance.get('PublicIpAddress'):
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('InstanceId'),
                                    ResourceName=instance.get('InstanceId'),
                                    ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unused_iam_access_keys(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            user_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for user in user_response:
                evaluated_resources += 1
                operation_args = dict(UserName=user.get('UserName', 'NA'))
                iam_user_response = run_aws_operation(
                    credentials, 'iam', 'list_access_keys', operation_args, response_key='AccessKeyMetadata')
                for access_key_usage in iam_user_response:
                    if access_key_usage.get('Status') == 'Inactive':
                        output.append(
                            OrderedDict(
                                ResourceId=user.get('UserName'),
                                ResourceName=user.get('UserName'),
                                ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_check_log_monitoring_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                instance_dict = ec2_instance_response.get('Reservations')
                for reservation in instance_dict:
                    for instance in reservation.get('Instances'):
                        evaluated_resources += 1
                        if instance.get('Monitoring', {}).get('State') != 'enabled':
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('InstanceId'),
                                    ResourceName=instance.get('InstanceId'),
                                    Resource='Instances',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_iam_user_exists(self, **kwargs):
        output = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            if not iam_response:
                output.append(OrderedDict(
                    ResourceId=service_account_id,
                    ResourceName=self.execution_args['service_account_name'],
                    Resource='IAM_Users',
                    ServiceAccountId=service_account_id,
                    ServiceAccountName=self.execution_args['service_account_name']))
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ec2_instance_using_iam_roles(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ec2_reservations in ec2_instance_response.get('Reservations'):
                    for ec2_instance_info in ec2_reservations.get('Instances'):
                        evaluated_resources += 1
                        if ec2_instance_info.get('IamInstanceProfile'):
                            output.append(
                                OrderedDict(
                                    ResourceId=ec2_instance_info.get('InstanceId'),
                                    ResourceName=ec2_instance_info.get('InstanceId'),
                                    Resource='Instances',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_elasticsearch_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            if (security_group_ip_permissions.get('FromPort') == 9200
                                    and security_group_ip_permissions.get('ToPort') == 9200):
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType='Security_Groups'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_https_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if (security_group_ip_permissions.get('IpProtocol')) != '-1':
                            if (security_group_ip_permissions.get('FromPort') == 443
                                    and security_group_ip_permissions.get('ToPort') == 443):
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType='Security_Groups'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_http_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if (security_group_ip_permissions.get('IpProtocol')) != '-1':
                            if (security_group_ip_permissions.get('FromPort') == 80
                                    and security_group_ip_permissions.get('ToPort') == 80):
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType='Security_Groups'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_inbound_access_on_uncommon_ports(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            ports = self.execution_args['args'].get('ports').replace(" ", "").split(',')
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region,
                        response_key='Security_Groups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups:
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if (security_group_ip_permissions.get('IpProtocol')) != '-1':
                            for port in ports:
                                if not port.isdigit():
                                    continue
                                if (security_group_ip_permissions.get('FromPort') == int(port)
                                        and security_group_ip_permissions.get('ToPort') == int(port)):
                                    for ip_address in security_group_ip_permissions.get('IpRanges'):
                                        if ip_address.get('CidrIp') == '0.0.0.0/0':
                                            security_group_compliant = False
                                    for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                        if ip_address.get('CidrIpv6') == '::/0':
                                            security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                Resource="SecurityGroups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_mongodb_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            if security_group_ip_permissions.get(
                                    'FromPort') == 27017 and security_group_ip_permissions.get('ToPort') == 27017:
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cloudtrail_enabled(self, **kwargs):
        output = list()
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    trail_response = run_aws_operation(
                        credentials,
                        'cloudtrail',
                        'describe_trails',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                if not trail_response.get('trailList'):
                    output.append(
                        OrderedDict(
                            ResourceId=self.execution_args['service_account_id'],
                            ResourceName=self.execution_args['service_account_name'],
                            ResourceType='CloudTrail'))

            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_mssql_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            if security_group_ip_permissions.get(
                                    'FromPort') == 1433 and security_group_ip_permissions.get('ToPort') == 1433:
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_mysql_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            if security_group_ip_permissions.get(
                                    'FromPort') == 3306 and security_group_ip_permissions.get('ToPort') == 3306:
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elasticsearch_in_vpc(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        domain_names = list()
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_domain_response = run_aws_operation(
                        credentials,
                        'es',
                        'list_domain_names',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_domain_response['DomainNames']:
                    evaluated_resources += 1
                    domain_names.append(domains['DomainName'])

                operation_args.update(DomainNames=domain_names)
                try:
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domains',
                        region_name=region,
                        operation_args=operation_args)

                    for domain in es_response['DomainStatusList']:
                        if 'Endpoint' in domain and domain['Endpoint'] != 'null':
                            output.append(
                                OrderedDict(
                                    ResourceId=domain['DomainName'],
                                    ResourceName=domain['DomainName'],
                                    ResourceType='es'))

                except Exception as e:
                    if "DomainStatus" in str(e):
                        continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elasticsearch_encrypted_at_rest(self, **kwargs):
        output = list()
        operation_args = {}
        domain_names = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]

            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'list_domain_names',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response['DomainNames']:
                    domain_names.append(domains['DomainName'])

                operation_args.update(DomainNames=domain_names)
                domains_response = run_aws_operation(
                    credentials,
                    'es',
                    'describe_elasticsearch_domains',
                    region_name=region,
                    operation_args=operation_args)
                for domain_status in domains_response['DomainStatusList']:
                    evaluated_resources += 1
                    if not domain_status.get('EncryptionAtRestOptions', {}).get('Enabled'):
                        output.append(
                            OrderedDict(
                                ResourceId=domain_status['DomainName'],
                                ResourceName=domain_status['DomainName'],
                                ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_deletion_protection_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response.get('LoadBalancers', []):
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerArn=elb['LoadBalancerArn'])
                    elb_log_info = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancer_attributes',
                        operation_args=operation_args,
                        region_name=region)
                    for logging_info in elb_log_info.get('Attributes', []):
                        if logging_info.get('Key') == 'deletion_protection.enabled' and logging_info.get(
                                'Value') == 'false':
                            output.append(
                                OrderedDict(
                                    ResourceId=elb['LoadBalancerName'],
                                    ResourceName=elb['LoadBalancerName'],
                                    ResourceType="ElasticLoadBalancing"))

            return output, evaluated_resources

        except Exception as e:
            raise Exception(str(e))

    def aws_root_account_hardware_mfa_enabled(self, **kwargs):
        output = list()
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            operation_args.update(AssignmentStatus='Any')
            mfa_response = run_aws_operation(
                credentials, 'iam', 'list_virtual_mfa_devices', operation_args=operation_args,
                response_key='VirtualMFADevices')
            for info in mfa_response:
                if info.get('SerialNumber'):
                    output.append(
                        OrderedDict(
                            ResourceId=info['SerialNumber'],
                            ResourceName=info['SerialNumber'],
                            ResourceType='iam'))
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def iam_root_access(self, check_type):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get(
                "service_account_name")
            credentials = self.execution_args['auth_values']
            try:
                content = run_aws_operation(
                    credentials, 'iam', 'get_credential_report').get(
                    'Content', None).decode()
            except Exception as err:
                if 'ReportNotPresent' in str(err):
                    content = run_aws_operation(
                        credentials, 'iam', 'get_credential_report').get(
                        'Content', None).decode()
                else:
                    raise err

            file_content = StringIO(content)
            csv_data = csv.reader(file_content, delimiter=",")
            try:
                next(csv_data)
            except StopIteration:
                return output, evaluated_resources
            for data in csv_data:
                evaluated_resources += 1
                try:
                    if check_type == 'access_key_active':
                        if data[0] == '<root_account>' and (
                                data[8] == 'true' or data[13] == 'true'):
                            output.append(
                                OrderedDict(
                                    ResourceId=data[0],
                                    ResourceName=data[0],
                                    Resource='iam',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=service_account_name))
                    elif check_type == 'mfa_active':
                        evaluated_resources = 1
                        if data[0] == '<root_account>' and data[7] == 'false':
                            output.append(
                                OrderedDict(
                                    ResourceId=data[0],
                                    ResourceName=data[0],
                                    Resource='iam',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=service_account_name))
                    elif check_type == 'root_account':
                        evaluated_resources = 1
                        if data[0] == '<root_account>':
                            password_last_changed = data[10]
                            print(password_last_changed)
                            date_object = datetime.strptime(
                                password_last_changed, "%Y-%m-%dT%H:%M:%S")
                            days_before = (datetime.now() - timedelta(days=30))
                            print(date_object)
                            if not days_before >= date_object:
                                # Non-Compliant
                                output.append(
                                    OrderedDict(
                                        ResourceId=data[0],
                                        ResourceName=data[0],
                                        ResourceType='IAM'))
                    elif check_type == 'root_account_signing_certificates':
                        evaluated_resources = 1
                        if data[0] == '<root_account>':
                            if (data[18].lower() == "false") or (data[20].lower() == "false"):
                                # Non-Compliant
                                output.append(
                                    OrderedDict(
                                        ResourceId=data[0],
                                        ResourceName=data[0],
                                        ResourceType='IAM'))
                    elif check_type == 'iam_initial_access_key':
                        user_creation_time_index = data[2]
                        access_key_1_last_rotated_index = data[9]
                        access_key_1_last_used_date_index = data[10]
                        user_creation_time = user_creation_time_index.split('+')[0]
                        if user_creation_time:
                            user_creation_time = datetime.strptime(
                                user_creation_time, "%Y-%m-%dT%H:%M:%S")
                        access_key_1_last_rotated = access_key_1_last_rotated_index.split('+')[0]
                        if access_key_1_last_rotated:
                            access_key_1_last_rotated = datetime.strptime(
                                access_key_1_last_rotated, "%Y-%m-%dT%H:%M:%S")
                        if user_creation_time == access_key_1_last_rotated and access_key_1_last_used_date_index == "N/A":
                            # Non-Compliant
                            output.append(
                                OrderedDict(
                                    ResourceId=data[0],
                                    ResourceName=data[0],
                                    ResourceType='IAM'))

                    elif check_type == 'canary_token':
                        operation_args1 = {}
                        user_response = run_aws_operation(
                            credentials, 'iam', 'list_users', response_key='Users')
                        for user in user_response:
                            operation_args1.update(UserName=user['UserName'])
                            attached_user = run_aws_operation(
                                credentials,
                                'iam',
                                'list_attached_user_policies',
                                operation_args=operation_args1,
                                response_key='AttachedPolicies')
                            if len(attached_user) == 0:
                                # Complaint
                                output.append(
                                    OrderedDict(
                                        ResourceId=user['UserName'],
                                        ResourceName=user['UserName'],
                                        ResourceType='IAM'))
                            else:
                                if data[0] == user['UserName']:
                                    if data[3].lower() == 'false' and data[4] == 'N/A':
                                        # Complaint
                                        output.append(
                                            OrderedDict(
                                                ResourceId=user['UserName'],
                                                ResourceName=user['UserName'],
                                                ResourceType='IAM'))

                                    elif data[8].lower() == 'true' or data[13].lower() == 'true':
                                        # Complaint
                                        output.append(
                                            OrderedDict(
                                                ResourceId=user['UserName'],
                                                ResourceName=user['UserName'],
                                                ResourceType='IAM'))

                                    else:
                                        # Non Complaint
                                        output.append(
                                            OrderedDict(
                                                ResourceId=user['UserName'],
                                                ResourceName=user['UserName'],
                                                ResourceType='IAM'))
                    elif check_type == 'date':
                        password_last_changed = data[5]
                        try:
                            date_object = datetime.strptime(
                                password_last_changed, "%Y-%m-%dT%H:%M:%S")
                            days_before = (datetime.now() - timedelta(days=30))
                            if not days_before >= date_object:
                                # Non-Compliant
                                output.append(
                                    OrderedDict(
                                        ResourceId=data[0],
                                        ResourceName=data[0],
                                        ResourceType='IAM'))
                        except ValueError as e:
                            output.append(
                                OrderedDict(
                                    ResourceId=data[0],
                                    ResourceName=data[0],
                                    ResourceType='IAM'))
                            continue
                except Exception as e:
                    continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_root_account_restriction(self, **kwargs):
        output, evaluated_resources = self.iam_root_access('root_account')
        return output, evaluated_resources

    def aws_ec2_ami_blacklisted(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            black_listed = self.execution_args['args'].get('black_listed', 'NA')
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Owners=['self', ])
                    ec2_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_images',
                        region_name=region,
                        operation_args=operation_args)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for images in ec2_response['Images']:
                    evaluated_resources += 1
                    if images.get('ImageId') in black_listed:
                        output.append(
                            OrderedDict(
                                ResourceId=images['ImageId'],
                                ResourceName=images['ImageId'],
                                ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_security_group_rfc_1918(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Filters=[
                        {
                            'Name': 'ip-permission.cidr',
                            'Values': [
                                '10.0.0.0/8',
                                '172.16.0.0/12',
                                '192.168.0.0/16'
                            ]
                        },
                    ])
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='SecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for security_group in security_groups:
                    evaluated_resources += 1
                    output.append(
                        OrderedDict(
                            ResourceId=security_group['GroupId'],
                            ResourceName=security_group['GroupId'],
                            ResourceType="SecurityGroup"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_webtier_ec2_instance_using_iam_roles(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            web_tier_tag_key = self.execution_args['args'].get("web_tier_tag_key")
            web_tier_tag_value = self.execution_args['args'].get("web_tier_tag_value")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation['Instances']:
                        evaluated_resources += 1
                        operation_args.update(Filters=[
                            {'Name': 'resource-id',
                             'Values': [instance['InstanceId']]}])
                        try:
                            tag_info = run_aws_operation(
                                credentials,
                                'ec2',
                                'describe_tags',
                                region_name=region,
                                operation_args=operation_args,
                                response_key='Tags')
                            for tag in tag_info:
                                if tag['Value'] == web_tier_tag_value and tag['Key'] == web_tier_tag_key:
                                    if not 'IamInstanceProfile' in instance:
                                        output.append(
                                            OrderedDict(
                                                ResourceId=instance['InstanceId'],
                                                ResourceName=instance['InstanceId'],
                                                ResourceType='EC2'))
                        except Exception as e:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_webtier_publicly_shared_ami(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            web_tier_tag_key = self.execution_args['args'].get("web_tier_tag_key")
            web_tier_tag_value = self.execution_args['args'].get("web_tier_tag_value")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Filters=[
                        {'Name': "tag:%s" % (web_tier_tag_key),
                         'Values': [
                             web_tier_tag_value]}],
                        Owners=['self', ])
                    ec2_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_images',
                        region_name=region,
                        operation_args=operation_args)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for images in ec2_response.get('Images', []):
                    evaluated_resources += 1
                    if images.get('Public'):
                        output.append(
                            OrderedDict(
                                ResourceId=images['ImageId'],
                                ResourceName=images['ImageId'],
                                ResourceType='EC2'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ebs_encrypted_with_cmk(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ebs_volumes_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_volumes',
                        region_name=region,
                        response_key='Volumes')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for ebs_volume in ebs_volumes_response:
                    evaluated_resources += 1
                    complaint = True
                    if ebs_volume.get('Encrypted'):
                        operation_args.update(KeyId=ebs_volume.get('KmsKeyId'))
                        kms_alias_response = run_aws_operation(
                            credentials,
                            'kms',
                            'list_aliases',
                            region_name=region,
                            operation_args=operation_args,
                            response_key='Aliases')
                        for kms_alias in kms_alias_response:
                            if kms_alias['AliasName'] == 'alias/aws/ebs':
                                output.append(
                                    OrderedDict(
                                        ResourceId=ebs_volume['VolumeId'],
                                        ResourceName=ebs_volume['VolumeId'],
                                        ResourceTYPE='EBS', ))
                                break

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_s3_operations(self, check_type):
        try:
            credentials = self.execution_args.get('auth_values')
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            operation_args = {}
            output = list()
            evaluated_resources = 0
            for bucket in s3_buckets['Buckets']:
                evaluated_resources += 1
                if check_type == 'READ_ACP':
                    operation_args.update(Bucket=bucket.get('Name', {}))
                    s3_bucket_acl = run_aws_operation(
                        credentials, 's3', 'get_bucket_acl', operation_args)
                    for s3_bucket_acl_grant in s3_bucket_acl.get('Grants', {}):
                        try:
                            if s3_bucket_acl_grant.get('Permission') == check_type and s3_bucket_acl_grant.get(
                                    'Grantee', {}).get(
                                'URI') == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                                output.append(
                                    OrderedDict(
                                        ResourceId=bucket['Name'],
                                        ResourceName=bucket['Name'],
                                        ResourceType='S3'))
                        except Exception as e:
                            raise Exception(e.message)
                elif check_type == 'WRITE_ACP':
                    operation_args.update(Bucket=bucket.get('Name', {}))
                    evaluated_resources += 1
                    s3_bucket_acl = run_aws_operation(
                        credentials, 's3', 'get_bucket_acl', operation_args)
                    for s3_bucket_acl_grant in s3_bucket_acl['Grants']:
                        try:
                            if s3_bucket_acl_grant.get('Permission') == check_type and s3_bucket_acl_grant.get(
                                    'Grantee', {}).get(
                                'URI') == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                                output.append(
                                    OrderedDict(
                                        ResourceId=bucket['Name'],
                                        ResourceName=bucket['Name'],
                                        ResourceType='S3'))
                        except Exception as e:
                            raise Exception(e.message)
                elif check_type == 'LifeCycle_Check':
                    operation_args.update(Bucket=bucket['Name'])
                    try:
                        s3_Bucket_LifeCycle_Config = run_aws_operation(
                            credentials, 's3', 'get_bucket_lifecycle_configuration', operation_args)
                    except Exception as e:
                        output.append(
                            OrderedDict(
                                ResourceId=bucket['Name'],
                                ResourceName=bucket['Name'],
                                ResourceType='S3'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_iam_unnecessary_access_keys(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(
                credentials,
                'iam',
                'list_users',
                response_key='Users')

            operation_args = {}
            for iam in iam_response['Users']:
                evaluated_resources += 1
                operation_args.update(UserName=iam['UserName'])
                iam_user_response = run_aws_operation(
                    credentials, 'iam', 'list_access_keys', operation_args)
                for access_key_usage in iam_user_response['AccessKeyMetadata']:
                    if access_key_usage['Status'] == 'Active':
                        output.append(
                            OrderedDict(
                                ResourceId=iam['UserName'],
                                ResourceName=iam['UserName'],
                                ResourceType='iam'))
            return output, evaluated_resources

        except Exception as e:
            raise Exception(str(e))

    def aws_s3_website_configuration_enabled(self):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            operation_args = {}
            for s3_bucket in s3_buckets['Buckets']:
                operation_args.update(Bucket=s3_bucket['Name'])
                s3_bucket_website = run_aws_operation(
                    credentials, 's3', 'get_bucket_website', operation_args)
                evaluated_resources += 1
                try:
                    if s3_bucket_website.get(
                            'IndexDocument', {}).get('Suffix') == '':
                        output.append(
                            OrderedDict(
                                ResourceId=s3_bucket['Name'],
                                ResourceName=s3_bucket['Name'],
                                ResourceType='s3'))
                except Exception as e:
                    raise Exception(e.messagestr(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_rotation_enabled(self, **kwargs):
        output = list()
        kmskey_list = list()
        operation_args = {}
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_response = run_aws_operation(
                        credentials,
                        'kms',
                        'list_keys',
                        region_name=region,
                        response_key='Keys')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for keys in kms_response:
                    operation_args.update(KeyId=keys['KeyId'])
                    kmskey_list.append(keys['KeyId'])
                    try:
                        key_response = run_aws_operation(
                            credentials,
                            'kms',
                            'get_key_rotation_status',
                            region_name=region,
                            operation_args=operation_args)
                        if not key_response['KeyRotationEnabled']:
                            output.append(
                                OrderedDict(
                                    ResourceId=keys['KeyId'],
                                    ResourceName=keys['KeyId'],
                                    ResourceType='KMS',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))
                    except Exception as e:
                        pass

            return output, len(kmskey_list)
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_cross_account_access_lacks_external_id_and_mfa(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_roles', response_key='Roles')
            for roles in iam_response:
                operation_args.update(RoleName=roles['RoleName'])
                evaluated_resources += 1
                iam_role_response = run_aws_operation(
                    credentials, 'iam', 'get_role', operation_args=operation_args)
                for statement in iam_role_response['Role']['AssumeRolePolicyDocument']['Statement']:
                    if 'AWS' in statement['Principal']:
                        if statement.get(
                                'Condition',
                                {}).get(
                            'Bool',
                            {}).get('aws:MultiFactorAuthPresent'):
                            output.append(
                                OrderedDict(
                                    ResourceId=roles['RoleName'],
                                    ResourceName=roles['RoleName'],
                                    ResourceType='IAM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_acm_certificate_required(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for listener_description in elb_response:
                    for ssl_info in listener_description['ListenerDescriptions']:
                        if ssl_info.get('Listener', {}).get(
                                'Protocol') == 'HTTPS':
                            if 'acm' not in ssl_info['Listener']['SSLCertificateId']:
                                output.append(
                                    OrderedDict(
                                        ResourceId=listener_description['LoadBalancerName'],
                                        ResourceName=listener_description['LoadBalancerName'],
                                        ResourceType="ELB"))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_patch_compliance_status_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation['Instances']:
                        evaluated_resources += 1
                        operation_args.update(
                            InstanceId=instance['InstanceId'])
                        ssm_response = run_aws_operation(
                            credentials,
                            'ssm',
                            'describe_instance_patches',
                            operation_args=operation_args,
                            region_name=region,
                            response_key='Patches')
                        if ssm_response['State'] == 'INSTALLED_PENDING_REBOOT' or ssm_response[
                            'State'] == 'INSTALLED_REJECTED' or ssm_response['State'] == 'MISSING' or ssm_response[
                            'State'] == 'FAILED':
                            output.append(
                                OrderedDict(
                                    ResourceId=instance['InstanceId'],
                                    ResourceName=instance['InstanceId'],
                                    ResourceType='SSM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_desired_instance_tenancy(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation['Instances']:
                        evaluated_resources += 1
                        if instance.get('Placement', {}).get(
                                'Tenancy') == 'host':
                            output.append(
                                OrderedDict(
                                    ResourceId=instance['InstanceId'],
                                    ResourceName=instance['InstanceId'],
                                    ResourceType="EC2"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_association_compliance_status_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation['Instances']:
                        evaluated_resources += 1
                        operation_args.update(
                            InstanceId=instance['InstanceId'])
                        ssm_response = run_aws_operation(
                            credentials,
                            'ssm',
                            'describe_instance_associations_status',
                            operation_args=operation_args,
                            region_name=region,
                            response_key='InstanceAssociationStatusInfos')
                        if ssm_response['Status'] != 'COMPLIANT':
                            output.append(
                                OrderedDict(
                                    ResourceId=instance['InstanceId'],
                                    ResourceName=instance['InstanceId'],
                                    ResourceType='SSM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_security_group_attached_to_eni(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region,
                        response_key='SecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups:
                    evaluated_resources += 1
                    operation_args.update(Filters=[
                        {
                            'Name': 'group-id',
                            'Values': [
                                security_group['GroupId'],
                            ]
                        },
                    ])
                    network_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_network_interfaces',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='NetworkInterfaces')
                    print(network_response)
                    if network_response == []:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group['GroupId'],
                                ResourceName=security_group['GroupId'],
                                ResourceType="security_group"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_instance_managed_by_system_manager(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args.get('auth_values', {})
            regions = [region.get('id') for region in self.execution_args.get('regions', {})]
            for region in regions:
                try:
                    instance_response = run_aws_operation(credentials, 'ec2', 'describe_instances',
                                                          region_name=region, response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in instance_response:
                    for ec2_instance_info in reservation.get('Instances', {}):
                        evaluated_resources += 1
                        if ec2_instance_info.get('State', {}).get('Name') == 'running':
                            operation_args = {"InstanceInformationFilterList": [
                                {
                                    'key': 'InstanceIds',
                                    'valueSet': [
                                        ec2_instance_info.get('InstanceId', {}),
                                    ]
                                },
                            ]}
                            ssm_response = run_aws_operation(credentials, 'ssm', 'describe_instance_information',
                                                             operation_args, region_name=region,
                                                             response_key='InstanceInformationList')
                            if ssm_response:
                                output.append(OrderedDict(ResourceId=ec2_instance_info.get('InstanceId'),
                                                          ResourceName=ec2_instance_info.get('InstanceId'),
                                                          Resource='SSM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_desired_instance_type(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args.get('auth_values', {})
            regions = [region.get('id') for region in self.execution_args.get('regions', {})]
            for region in regions:
                try:
                    instance_response = run_aws_operation(credentials, 'ec2', 'describe_instances',
                                                          region_name=region, response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in instance_response:
                    for ec2_instance_info in reservation.get('Instances', {}):
                        evaluated_resources += 1
                        if ec2_instance_info.get('State', {}).get('Name') == 'running':
                            if ec2_instance_info.get('InstanceType'):
                                output.append(OrderedDict(ResourceId=ec2_instance_info.get('InstanceId'),
                                                          ResourceName=ec2_instance_info.get('InstanceId'),
                                                          Resource='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_fms_webacl_rulegroup_association_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    fms_response = run_aws_operation(
                        credentials,
                        'fms',
                        'list_policies',
                        region_name=region,
                        response_key='PolicyList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for policy in fms_response:
                    evaluated_resources += 1
                    operation_args.update(PolicyId=policy['PolicyId'])
                    fms_policy_response = run_aws_operation(
                        credentials,
                        'fms',
                        'get_policy',
                        region_name=region,
                        operation_args=operation_args)
                    policy_data = json.loads(
                        fms_policy_response.get('Policy', {}).get('SecurityServicePolicyData', {}).get(
                            'ManagedServiceData'))
                    try:
                        if not policy_data['ruleGroups']:
                            output.append(
                                OrderedDict(
                                    ResourceId=policy['PolicyId'],
                                    ResourceName=policy['PolicyId'],
                                    ResourceType='fms'))
                    except KeyError as e:
                        output.append(
                            OrderedDict(
                                ResourceId=policy['PolicyId'],
                                ResourceName=policy['PolicyId'],
                                ResourceType='WAF'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_fms_webacl_resource_policy_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    fms_response = run_aws_operation(
                        credentials,
                        'fms',
                        'list_policies',
                        region_name=region,
                        response_key='PolicyList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for policy in fms_response:
                    evaluated_resources += 1
                    operation_args.update(PolicyId=policy['PolicyId'])
                    fms_policy_response = run_aws_operation(
                        credentials,
                        'fms',
                        'get_policy',
                        region_name=region,
                        operation_args=operation_args)
                    if fms_policy_response.get('Policy', {}).get('SecurityServicePolicyData', {}).get(
                            'Type') != 'WAF' or fms_policy_response.get('Policy', {}).get('SecurityServicePolicyData',
                                                                                          {}).get('Type') != 'WAFV2':
                        output.append(
                            OrderedDict(
                                ResourceId=policy['PolicyId'],
                                ResourceName=policy['PolicyId'],
                                ResourceType='WAF'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_kms_cmk_not_sheduled_for_deletion(
            self,
            **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_key_response = run_aws_operation(
                        credentials, 'kms', 'list_keys', region_name=region, response_key='Keys')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for key in kms_key_response:
                    evaluated_resources += 1
                    operation_args.update(KeyId=key['KeyId'])
                    kms_info = run_aws_operation(
                        credentials,
                        'kms',
                        'describe_key',
                        region_name=region,
                        operation_args=operation_args)
                    if kms_info.get('KeyMetadata', {}).get(
                            'KeyState') == 'PendingDeletion':
                        output.append(
                            OrderedDict(
                                ResourceId=key['KeyId'],
                                ResourceName=key['KeyId'],
                                ResourceType='KMS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_fms_shield_resource_policy_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    fms_response = run_aws_operation(
                        credentials,
                        'fms',
                        'list_policies',
                        region_name=region,
                        response_key='PolicyList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for policy in fms_response:
                    evaluated_resources += 1
                    operation_args.update(PolicyId=policy['PolicyId'])
                    fms_policy_response = run_aws_operation(
                        credentials,
                        'fms',
                        'get_policy',
                        region_name=region,
                        operation_args=operation_args)
                    if fms_policy_response.get('Policy', {}).get('SecurityServicePolicyData', {}).get(
                            'Type') != 'SHIELD_ADVANCED':
                        output.append(
                            OrderedDict(
                                ResourceId=policy['PolicyId'],
                                ResourceName=policy['PolicyId'],
                                ResourceType='FMS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_lambda_inside_vpc(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        credentials = self.execution_args['auth_values']
        try:
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    operation_args.update(
                        FunctionName=function['FunctionName'])
                    function_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'get_function',
                        region_name=region,
                        operation_args=operation_args)
                    try:
                        function_response['Configuration']['VpcConfig']
                    except Exception as e:
                        if 'VpcConfig' in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=function['FunctionName'],
                                    ResourceName=function['FunctionName'],
                                    ResourceType='Lambda'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_lambda_concurrency_check(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args.get('auth_values', {})
            regions = [region.get('id') for region in self.execution_args.get('regions', {})]
            for region in regions:
                try:
                    list_functions_response = run_aws_operation(credentials, 'lambda', 'list_functions',
                                                                region_name=region, response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in list_functions_response:
                    evaluated_resources += 1
                    operation_args = {}
                    operation_args.update(FunctionName=function.get('FunctionName'))
                    list_aliases_response = run_aws_operation(credentials, 'lambda', 'list_aliases', operation_args,
                                                              region_name=region, response_key='Aliases')
                    for aliases in list_aliases_response:
                        operation_args.update(Qualifier=aliases.get('Name'))
                        try:
                            get_provisioned_response = run_aws_operation(credentials, 'lambda',
                                                                         'get_provisioned_concurrency_config',
                                                                         operation_args, region_name=region)
                        except Exception as e:
                            if 'ProvisionedConcurrencyConfigNotFoundException' in str(e):
                                continue
                            raise e.message

                        if get_provisioned_response:
                            output.append(OrderedDict(ResourceId=function.get('FunctionName'),
                                                      ResourceName=function.get('FunctionName'),
                                                      Resource='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_redshift_cluster_public_access_check(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args.get('auth_values', {})
            regions = [region.get('id') for region in self.execution_args.get('regions', {})]
            for region in regions:
                try:
                    redshift_cluster_name = run_aws_operation(credentials, 'redshift', 'describe_clusters',
                                                              region_name=region, response_key='Clusters')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster_info in redshift_cluster_name:
                    evaluated_resources += 1
                    operation_args = {}
                    operation_args.update(ClusterIdentifier=cluster_info.get('ClusterIdentifier'))
                    redshift_cluster = run_aws_operation(credentials, 'redshift', 'describe_clusters',
                                                         operation_args, region_name=region, response_key='Clusters')
                    for cluster in redshift_cluster:
                        if cluster.get('PendingModifiedValues', {}).get('PubliclyAccessible'):
                            output.append(OrderedDict(ResourceId=cluster.get('ClusterIdentifier'),
                                                      ResourceName=cluster.get('ClusterIdentifier'),
                                                      Resource='Redshift'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_support_access(self):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args.get('auth_values', {})
            try:
                response_iterator = run_aws_operation(credentials, 'iam', 'list_policies', response_key='Policies')
            except Exception as e:
                raise Exception(
                    'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                        str(e)))
            for policies in response_iterator:
                evaluated_resources += 1
                operation_args.update(PolicyArn=policies.get('Arn', {}))
                entity_response = run_aws_operation(credentials, 'iam', 'list_entities_for_policy',
                                                    operation_args)
                if len(entity_response.get('PolicyRoles')) == 0:
                    # Non-Compliants
                    output.append(OrderedDict(ResourceId=policies.get('PolicyName'),
                                              ResourceName=policies.get('PolicyName'),
                                              Resource='IAM'))
            return output, evaluated_resources

        except Exception as e:
            raise Exception(e.message)

    def aws_vpc_peering_least_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = self.execution_args['regions']
            for region in regions:
                try:
                    operation_args.update(
                        Filters=[
                            {
                                'Name': 'status-code',
                                'Values': [
                                    'active',
                                ]
                            },
                        ]
                    )
                    aws_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpc_peering_connections',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='VpcPeeringConnections')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for info in aws_response:
                    evaluated_resources += 1
                    operation_args.update(
                        Filters=[
                            {
                                'Name': 'route.vpc-peering-connection-id',
                                'Values': [
                                    info['VpcPeeringConnectionId'],
                                ]},
                        ])
                    ec2_client = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_route_tables',
                        operation_args=operation_args,
                        region_name=region)
                    for more_info in ec2_client['RouteTables']:
                        for route in more_info['Routes']:
                            value = str(route['DestinationCidrBlock'])[-2:]
                            try:
                                if int(value) <= 28:
                                    output.append(
                                        OrderedDict(
                                            ResourceId=info['VpcPeeringConnectionId'],
                                            ResourceName=info['VpcPeeringConnectionId'],
                                            ResourceType='vpc'))
                            except Exception as e:
                                if 'invalid literal' in str(e):
                                    output.append(
                                        OrderedDict(
                                            ResourceId=info['VpcPeeringConnectionId'],
                                            ResourceName=info['VpcPeeringConnectionId'],
                                            ResourceType='vpc'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_vpn_tunnel_redundancy(
            self,
            **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            filter_name = self.execution_args["filter_name"]
            filter_values = self.execution_args["filter_values"]
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Filters=[
                        {'Name': '%s' % (filter_name),
                         'Values': ['%s' % (filter_values)]},
                    ], )
                    vpn_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpn_connections',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for vpn_connection in vpn_response['VpnConnections']:
                    evaluated_resources += 1
                    for telemetry in vpn_connection['VgwTelemetry']:
                        if telemetry['Status'] == "DOWN":
                            output.append(
                                OrderedDict(
                                    ResourceId=vpn_connection['VpnConnectionId'],
                                    ResourceName=vpn_connection['VpnConnectionId'],
                                    ResourceType='ec2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_iam_valid_iam_identity_providers(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            date_condition = datetime.date(2014, 8, 1)
            credentials = self.execution_args['auth_values']
            saml_providers = run_aws_operation(
                credentials, 'iam', 'list_saml_providers')
            for arn in saml_providers['SAMLProviderList']:
                evaluated_resources += 1
                for arn in saml_providers:
                    if 'CreateDate' in arn:
                        createddate = arn['CreateDate'].date()
                        if createddate < date_condition:
                            output.append(
                                OrderedDict(
                                    ResourceId=arn['Arn'],
                                    ResourceName=arn['Arn'],
                                    ResourceType='iam'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_rds_instance_enable_log_exports(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for dbinstance in rds_response:
                    evaluated_resources += 1
                    try:
                        dbinstance["EnabledCloudwatchLogsExports"]
                    except Exception as e:
                        if "EnabledCloudwatchLogsExports" in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=dbinstance['DBInstanceIdentifier'],
                                    ResourceName=dbinstance['DBInstanceIdentifier'],
                                    ResourceType='rds'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_instance_deletion_protection(self, **kwargs):
        try:
            output, evaluated_resources = self.check_rds_config(
                'DeletionProtection')
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_encrypted_with_kms_customer_master_keys(self):
        output = list()
        evaluated_resources = 0
        master_alias = 'alias/aws/rds'
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_instances = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                    kms_alias = run_aws_operation(
                        credentials,
                        'kms',
                        'list_aliases',
                        region_name=region,
                        response_key='Aliases')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for each_instance in db_instances:
                    evaluated_resources += 1
                    db_instance_name = each_instance["DBInstanceIdentifier"]
                    if each_instance['StorageEncrypted']:
                        temp_kmskey_id = each_instance.get('KmsKeyId', {})
                        kmskey_id = str(temp_kmskey_id).split('/')[1]
                        for each_kms_alias in kms_alias:
                            TargetKeyId = each_kms_alias.get('TargetKeyId', {})
                            if TargetKeyId == kmskey_id:
                                output.append(OrderedDict(ResourceId=db_instance_name, ResourceName=db_instance_name,
                                                          Resource='rds'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_rds_event_notification(self):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get("service_account_name")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                evaluated_resources += 1
                try:
                    rds_event_metadata = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_event_subscriptions',
                        region_name=region,
                        response_key='EventSubscriptionsList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                if not rds_event_metadata:
                    output.append(
                        OrderedDict(
                            ResourceId=service_account_id,
                            ResourceName=service_account_id,
                            ResourceType='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_master_username(self):
        output, evaluated_resources = self.common_rds_describe_db_instances_fun(
            'masteruser')
        return output, evaluated_resources

    def aws_kms_cross_account_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_response = run_aws_operation(
                        credentials,
                        'kms',
                        'list_aliases',
                        region_name=region,
                        response_key='Aliases')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for key in kms_response:
                    evaluated_resources += 1
                    try:
                        operation_args.update(
                            KeyId=key['TargetKeyId'], PolicyName='default')
                    except Exception as e:
                        if 'TargetKeyId' in str(e):
                            continue
                    try:
                        key_info = run_aws_operation(
                            credentials,
                            'kms',
                            'get_key_policy',
                            region_name=region,
                            operation_args=operation_args)
                    except Exception as e:
                        if 'No such policy exists' in str(e):
                            continue
                        raise e
                    Policy = json.loads(key_info['Policy'])
                    if 'Statement' in Policy:
                        for principal in Policy['Statement']:
                            if principal['Principal']['AWS'] == "*":
                                output.append(
                                    OrderedDict(
                                        ResourceId=key['TargetKeyId'],
                                        ResourceName=key['TargetKeyId'],
                                        ResourceType='kms'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_vpc_peering_least_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = self.execution_args['regions']
            for region in regions:
                try:
                    operation_args.update(
                        Filters=[
                            {
                                'Name': 'status-code',
                                'Values': [
                                    'active',
                                ]
                            },
                        ]
                    )
                    aws_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpc_peering_connections',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='VpcPeeringConnections')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for info in aws_response:
                    evaluated_resources += 1
                    operation_args.update(
                        Filters=[
                            {
                                'Name': 'route.vpc-peering-connection-id',
                                'Values': [
                                    info['VpcPeeringConnectionId'],
                                ]},
                        ])
                    ec2_client = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_route_tables',
                        operation_args=operation_args,
                        region_name=region)
                    for more_info in ec2_client['RouteTables']:
                        for route in more_info['Routes']:
                            value = str(route['DestinationCidrBlock'])[-2:]
                            try:
                                if int(value) <= 28:
                                    output.append(
                                        OrderedDict(
                                            ResourceId=info['VpcPeeringConnectionId'],
                                            ResourceName=info['VpcPeeringConnectionId'],
                                            ResourceType='vpc'))
                            except Exception as e:
                                if 'invalid literal' in str(e):
                                    output.append(
                                        OrderedDict(
                                            ResourceId=info['VpcPeeringConnectionId'],
                                            ResourceName=info['VpcPeeringConnectionId'],
                                            ResourceType='vpc'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_managedinstance_applications_blacklisted(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get(
                "service_account_name")
            blocklisted_instance_type = self.execution_args['blocklisted_instance_type']
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                operation_args = {"Filters": [
                    {
                        'Name': 'instance-state-name',
                        'Values': [
                            "running",
                        ]
                    },
                    {
                        'Name': 'instance-type',
                        'Values': [
                            blocklisted_instance_type,
                        ]
                    },
                ]}
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation['Instances']:
                        evaluated_resources += 1
                        output.append(
                            OrderedDict(
                                ResourceId=instance['InstanceId'],
                                ResourceName=instance['InstanceId'],
                                Resource='EC2',
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=service_account_name))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_attach_policy_iam_roles_app_tier_ec2_instances(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            app_tier_tag = self.execution_args["app_tier_tag"]
            app_tier_tag_value = self.execution_args["app_tier_tag_value"]
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ec2_reservations in ec2_instance_response:
                    for ec2_instance_info in ec2_reservations['Instances']:
                        evaluated_resources += 1
                        operation_args.update(
                            Filters=[
                                {
                                    'Name': 'resource-id',
                                    'Values': [
                                        ec2_instance_info['InstanceId'],
                                    ]
                                },
                            ]
                        )
                        ec2_tags = run_aws_operation(
                            credentials,
                            'ec2',
                            'describe_tags',
                            operation_args=operation_args,
                            region_name=region,
                            response_key='Tags')

                        for tag in ec2_tags:
                            if tag['Key'] != app_tier_tag and tag['Value'] != app_tier_tag_value:
                                output.append(
                                    OrderedDict(
                                        ResourceId=ec2_instance_info['InstanceId'],
                                        ResourceName=ec2_instance_info['InstanceId'],
                                        ResourceType="EC2"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_attach_policy_iam_roles_web_tier_ec2_instances(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            web_tier_tag = self.execution_args["web_tier_tag"]
            web_tier_tag_value = self.execution_args["web_tier_tag_value"]
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ec2_reservations in ec2_instance_response:
                    for ec2_instance_info in ec2_reservations['Instances']:
                        evaluated_resources += 1
                        operation_args.update(
                            Filters=[
                                {
                                    'Name': 'resource-id',
                                    'Values': [
                                        ec2_instance_info['InstanceId'],
                                    ]
                                },
                            ]
                        )
                        ec2_tags = run_aws_operation(
                            credentials,
                            'ec2',
                            'describe_tags',
                            operation_args=operation_args,
                            region_name=region,
                            response_key='Tags')

                        for tag in ec2_tags:
                            if tag['Key'] != web_tier_tag and tag['Value'] != web_tier_tag_value:
                                output.append(
                                    OrderedDict(
                                        ResourceId=ec2_instance_info['InstanceId'],
                                        ResourceName=ec2_instance_info['InstanceId'],
                                        ResourceType="EC2"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_vpc_peer_connections_acc_outside_organization(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            valid_account_list = list(map(str.strip, self.execution_args['args']['valid_account_list'].split(',')))
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(
                        Filters=[
                            {
                                'Name': 'status-code',
                                'Values': [
                                    'active',
                                ]
                            },
                        ]
                    )
                    aws_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpc_peering_connections',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='VpcPeeringConnections')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for info in aws_response:
                    evaluated_resources += 1
                    if info.get(
                            'RequesterVpcInfo',
                            {}).get('OwnerId') not in valid_account_list and info.get(
                        'AccepterVpcInfo',
                        {}).get('OwnerId') not in valid_account_list:
                        output.append(
                            OrderedDict(
                                ResourceId=info['VpcPeeringConnectionId'],
                                ResourceName=info['VpcPeeringConnectionId'],
                                ResourceType='ec2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elasticache_redis_cluster_automatic_backup(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args.get('auth_values')
            snapshot_retention_period = self.execution_args.get('snapshot_retention_period')
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elasticache_response = run_aws_operation(
                        credentials,
                        'elasticache',
                        'describe_replication_groups',
                        region_name=region,
                        response_key='ReplicationGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
            for replication in elasticache_response:
                evaluated_resources += 1
                if replication['SnapshotRetentionLimit'] < snapshot_retention_period:
                    output.append(
                        OrderedDict(
                            ResourceId=replication['ReplicationGroupId'],
                            ResourceName=replication['ReplicationGroupId'],
                            ResourceType='elasticache'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_rds_dms_replication_not_public(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args.get('auth_values')
            snapshot_retention_period = self.execution_args.get('snapshot_retention_period')
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    dms_response = run_aws_operation(
                        credentials,
                        'dms',
                        'describe_replication_instances',
                        region_name=region,
                        response_key='ReplicationGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
            for replication in dms_response:
                evaluated_resources += 1
                if replication['PubliclyAccessible']:
                    output.append(
                        OrderedDict(
                            ResourceId=replication['ReplicationInstanceIdentifier'],
                            ResourceName=replication['ReplicationInstanceIdentifier'],
                            ResourceType='DMS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def common_ssl_tls_server_certificate_to_tier(self, check_type):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        # project Related
        POLICY_NAME_LIST = ['ELBSecurityPolicy-2016-08',
                            'ELBSecurityPolicy-TLS-1-2-2017-01',
                            'ELBSecurityPolicy-TLS-1-1-2017-01',
                            'ELBSecurityPolicy-2015-05',
                            'ELBSecurityPolicy-2015-03',
                            'ELBSecurityPolicy-2015-02',
                            'ELBSecurityPolicy-2014-10',
                            'ELBSecurityPolicy-2014-01',
                            'ELBSecurityPolicy-2011-08',
                            'ELBSample-ELBDefaultNegotiationPolicy',
                            'ELBSample-ELBDefaultCipherPolicy',
                            'ELBSample-OpenSSLDefaultNegotiationPolicy',
                            'ELBSample-OpenSSLDefaultCipherPolicy']
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                if len(elb_response) > 0:
                    for _elb in elb_response:
                        evaluated_resources += 1
                        operation_args.update(
                            LoadBalancerNames=[
                                _elb['LoadBalancerName']])
                        tag_response = run_aws_operation(
                            credentials, 'elb', 'describe_tags', operation_args, region_name=region)
                        for tags in tag_response['TagDescriptions']:
                            try:
                                if check_type == 'health_check':
                                    if tags['Tags']:
                                        response = run_aws_operation(
                                            credentials,
                                            'elb',
                                            'describe_load_balancers',
                                            operation_args,
                                            region_name=region,
                                            response_key='LoadBalancerDescriptions')
                                        for load_description in response:
                                            if load_description['HealthCheck']:
                                                if 'TCP' not in load_description['HealthCheck'][
                                                    'Target'] or 'SSL' not in \
                                                        load_description['HealthCheck']['Target']:
                                                    output.append(
                                                        OrderedDict(
                                                            ResourceId=load_description['HealthCheck']['Target'],
                                                            ResourceName=load_description['HealthCheck']['Target'],
                                                            ResourceType='ELB'))
                                    else:
                                        output.append(
                                            OrderedDict(
                                                ResourceId=_elb['LoadBalancerName'],
                                                ResourceName=_elb['LoadBalancerName'],
                                                ResourceType='ELB'))
                                else:
                                    for tag in tags['Tags']:
                                        if check_type == 'app_tier_tag':
                                            if tag['Key'] == 'app_tier_tag' and tag['Value'] == 'app_tier_tag_value':
                                                output = self.common_ssl_tls_server(
                                                    credentials, region, output)
                                        elif check_type == 'web_tier_tag':
                                            if tag['Key'] == 'web_tier_tag' and tag['Value'] == 'web_tier_tag_value':
                                                output = self.common_ssl_tls_server(
                                                    credentials, region, output)
                                        elif check_type == 'elb_security':
                                            if tags['Tags']:
                                                operation_args = {}
                                                operation_args.update(
                                                    LoadBalancerName=_elb['LoadBalancerName'])
                                                balance_response = run_aws_operation(
                                                    credentials, 'elb', 'describe_load_balancer_policies',
                                                    operation_args, region_name=region)
                                                for balancer in balance_response['PolicyDescriptions']:
                                                    operation_args.update(
                                                        PolicyNames=[balancer['PolicyName']])
                                                    policy_response = run_aws_operation(
                                                        credentials, 'elb', 'describe_load_balancer_policies',
                                                        operation_args, region_name=region)
                                                    for policy in policy_response['PolicyDescriptions']:
                                                        if any(desc['AttributeName'] == 'Reference-Security-Policy' for
                                                               desc in
                                                               policy['PolicyAttributeDescriptions']) and balancer[
                                                            'PolicyName'] in POLICY_NAME_LIST:
                                                            # Non-Compliant
                                                            output.append(
                                                                OrderedDict(
                                                                    ResourceId=balancer['PolicyName'],
                                                                    ResourceName=balancer['PolicyName'],
                                                                    ResourceType='ELB'))
                                        elif check_type == 'listener_security':
                                            if tags['Tags']:
                                                operation_args = {}
                                                operation_args.update(LoadBalancerNames=[
                                                    _elb['LoadBalancerName']])
                                                response = run_aws_operation(
                                                    credentials, 'elb', 'describe_load_balancers', operation_args,
                                                    region_name=region)
                                                if response['LoadBalancerDescriptions']:
                                                    for desc in response['LoadBalancerDescriptions']:
                                                        for listener_desc in desc['ListenerDescriptions']:
                                                            if listener_desc['Listener']['Protocol'] in [
                                                                'HTTPS', 'SSL']:
                                                                # Non-Compliant
                                                                output.append(
                                                                    OrderedDict(
                                                                        ResourceId=_elb['LoadBalancerName'],
                                                                        ResourceName=_elb['LoadBalancerName'],
                                                                        ResourceType='ELB'))
                                        elif check_type == 'security_policy':
                                            if tag['Key'] == 'web_tier_tag' and tag['Value'] == 'web_tier_tag_value':
                                                operation_args = {}
                                                operation_args.update(
                                                    LoadBalancerName=_elb['LoadBalancerName'])
                                                balance_response = run_aws_operation(
                                                    credentials, 'elb', 'describe_load_balancer_policies',
                                                    operation_args, region_name=region)
                                                for balancer in balance_response['PolicyDescriptions']:
                                                    operation_args.update(
                                                        PolicyNames=[balancer['PolicyName']])
                                                    policy_response = run_aws_operation(
                                                        credentials, 'elb', 'describe_load_balancer_policies',
                                                        operation_args, region_name=region)
                                                    for policy in policy_response['PolicyDescriptions']:
                                                        if any(desc['AttributeName'] == 'Reference-Security-Policy' for
                                                               desc in policy['PolicyAttributeDescriptions']) and \
                                                                balancer['PolicyName'] in POLICY_NAME_LIST:
                                                            # NON_COMPLIANT
                                                            output.append(
                                                                OrderedDict(
                                                                    ResourceId=balancer['PolicyName'],
                                                                    ResourceName=balancer['PolicyName'],
                                                                    ResourceType='ELB'))
                            except Exception as e:
                                raise Exception(str(e))
            if output:
                policy_output = {v['ResourceId']: v for v in output}.values()
                output = policy_output
                return output, evaluated_resources
            else:
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_add_ssl_tls_server_certificate_to_app_tier_elbs(self):
        output, evaluated_resources = self.common_ssl_tls_server_certificate_to_tier(
            'app_tier_tag')
        return output, evaluated_resources

    def aws_add_ssl_tls_server_certificate_to_web_tier_elbs(self):
        output, evaluated_resources = self.common_ssl_tls_server_certificate_to_tier(
            'web_tier_tag')
        return output, evaluated_resources

    def aws_app_tier_elb_security_policy(self):
        output, evaluated_resources = self.common_ssl_tls_server_certificate_to_tier(
            'elb_security')
        return output, evaluated_resources

    def aws_app_tier_elb_listener_security(self):
        output, evaluated_resources = self.common_ssl_tls_server_certificate_to_tier(
            'listener_security')
        return output, evaluated_resources

    def aws_cloudtrail_bucket_mfa_delete_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                credentials = self.execution_args['auth_values']
                cloudtrail_reponse = run_aws_operation(
                    credentials,
                    'cloudtrail',
                    'describe_trails',
                    region_name=region)
                for trail in cloudtrail_reponse['trailList']:
                    evaluated_resources += 1
                    operation_args.update(Bucket=trail['S3BucketName'])
                    s3_bucket_MFA_delete_enabled = run_aws_operation(
                        credentials, 's3', 'get_bucket_versioning', operation_args=operation_args)
                    try:
                        if s3_bucket_MFA_delete_enabled['MFADelete'] != 'Enabled':
                            output.append(
                                OrderedDict(
                                    ResourceId=trail['S3BucketName'],
                                    ResourceName=trail['S3BucketName'],
                                    ResourceType='S3'))
                    except Exception as e:
                        if 'MFADelete' in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=trail['S3BucketName'],
                                    ResourceName=trail['S3BucketName'],
                                    ResourceType='S3'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cloudtrail_bucket_publicly_accessible(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        permission_checking_list = ['READ', 'WRITE', 'READ_ACP', 'WRITE_ACP']
        credentials = self.execution_args['auth_values']
        try:
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                cloudtrail_reponse = run_aws_operation(
                    credentials, 'cloudtrail', 'describe_trails', region_name=region)
                for trail in cloudtrail_reponse['trailList']:
                    evaluated_resources += 1
                    operation_args.update(Bucket=trail['S3BucketName'])
                    s3_bucket_acl = run_aws_operation(
                        credentials, 's3', 'get_bucket_acl', operation_args=operation_args)
                    for s3_bucket_acl_grant in s3_bucket_acl['Grants']:
                        try:
                            if s3_bucket_acl_grant['Permission'] in permission_checking_list and s3_bucket_acl_grant[
                                'Grantee']['URI'] == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                                output.append(
                                    OrderedDict(
                                        ResourceId=trail['Name'],
                                        ResourceName=trail['Name'],
                                        ResourceType='cloudtrail'))
                            bucket_policy = run_aws_operation(
                                credentials, 's3', 'get_bucket_policy', operation_args=operation_args)
                            policy = bucket_policy['Policy']
                            policy = json.loads(policy)
                            for statement in policy['Statement']:
                                if statement['Effect'] == "Allow" and statement['Principal'].values(
                                ) == "*":
                                    output.append(
                                        OrderedDict(
                                            ResourceId=trail['Name'],
                                            ResourceName=trail['Name'],
                                            ResourceType='cloudtrail'))
                        except Exception as e:
                            if 'URI' in str(e):
                                continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_dns_compliant(self):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            for s3_bucket in s3_buckets['Buckets']:
                evaluated_resources += 1
                if s3_bucket['Name'].startswith(
                        '.') and s3_bucket.endswith('.') and s3_bucket in '..':
                    output.append(
                        OrderedDict(
                            ResourceId=s3_bucket['Name'],
                            ResourceName=s3_bucket['Name'],
                            ResourceType='s3'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_ec2_classice_elastic_ip_address_limit(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    address = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_addresses',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                ip_list = list()
                for public_ip in address['Addresses']:
                    evaluated_resources += 1
                    if 'PublicIp' in public_ip:
                        ip_value = public_ip['PublicIp']
                        ip_list.append(ip_value)
                if len(ip_list) >= 5:
                    output.append(
                        OrderedDict(
                            ResourceId=public_ip['PublicIp'],
                            ResourceName=public_ip['PublicIp'],
                            ResourceType='ec2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_ec2_instance_naming_conventions(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            valid_tags = self.execution_args['valid_tags']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation['Instances']:
                        evaluated_resources += 1
                        if 'Tags' in instance:
                            for value in instance['Tags']:
                                if value['Value'] not in valid_tags:
                                    output.append(
                                        OrderedDict(
                                            ResourceId=instance['InstanceId'],
                                            ResourceName=instance['InstanceId'],
                                            ResourceType="EC2"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_elb_connection_draining_enabled(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerName=elb['LoadBalancerName'])
                    elb_info = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancer_attributes',
                        region_name=region,
                        operation_args=operation_args)
                    if not elb_info['LoadBalancerAttributes']['ConnectionDraining']['Enabled']:
                        output.append(
                            OrderedDict(
                                ResourceId=elb['LoadBalancerName'],
                                ResourceName=elb['LoadBalancerName'],
                                ResourceType='elb'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_insecure_ssl_ciphers_protocols(self, type):
        try:
            output = list()
            evaluated_resources = 0
            operation_args = {}
            insecure_ciphers = [
                'RC2-CBC-MD5',
                'PSK-AES256-CBC-SHA',
                'PSK-3DES-EDE-CBC-SHA',
                'KRB5-DES-CBC3-SHA',
                'KRB5-DES-CBC3-MD5',
                'PSK-AES128-CBC-SHA',
                'PSK-RC4-SHA',
                'KRB5-RC4-SHA',
                'KRB5-RC4-MD5',
                'KRB5-DES-CBC-SHA',
                'KRB5-DES-CBC-MD5',
                'EXP-EDH-RSA-DES-CBC-SHA',
                'EXP-EDH-DSS-DES-CBC-SHA',
                'EXP-ADH-DES-CBC-SHA',
                'EXP-DES-CBC-SHA',
                'EXP-RC2-CBC-MD5',
                'EXP-KRB5-RC2-CBC-SHA',
                'EXP-KRB5-DES-CBC-SHA',
                'EXP-KRB5-RC2-CBC-MD5',
                'EXP-KRB5-DES-CBC-MD5',
                'EXP-ADH-RC4-MD5',
                'EXP-RC4-MD5',
                'EXP-KRB5-RC4-SHA',
                'EXP-KRB5-RC4-MD5']
            insecure_protocols = ['Protocol-SSLv2',
                                  'Protocol-SSLv3',
                                  'Protocol-TLSv1']
            secure_cipher_policy = ['ELBSecurityPolicy-2016-08']
            secure_protocol_policy = [
                'ELBSecurityPolicy-TLS-1-2-2017-01',
                'ELBSecurityPolicy-TLS-1-1-2017-01',
                'ELBSecurityPolicy-2016-08']
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))

                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerName=elb['LoadBalancerName'])
                    elb_policies_info = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancer_policies',
                        region_name=region,
                        operation_args=operation_args)
                    for elb_policy in elb_policies_info['PolicyDescriptions']:
                        policy_flag = True
                        for policy_attribute in elb_policy['PolicyAttributeDescriptions']:
                            if type == "Ciphers":
                                if policy_attribute['AttributeName'] == 'Reference-Security-Policy':
                                    if policy_attribute['AttributeValue'] not in secure_cipher_policy:
                                        policy_flag = False
                                if (policy_attribute['AttributeName']
                                        in insecure_ciphers and policy_attribute['AttributeValue'] == 'true'):
                                    policy_flag = False
                            elif type == "Protocols":
                                if policy_attribute['AttributeName'] == 'Reference-Security-Policy':
                                    if policy_attribute['AttributeValue'] not in secure_protocol_policy:
                                        policy_flag = False
                                if (policy_attribute['AttributeName']
                                        in insecure_protocols and policy_attribute['AttributeValue'] == 'true'):
                                    policy_flag = False
                            else:
                                if policy_attribute['AttributeName'] == 'Reference-Security-Policy':
                                    if policy_attribute['AttributeValue'] not in secure_protocol_policy:
                                        policy_flag = False

                        if not policy_flag:
                            output.append(
                                OrderedDict(
                                    ResourceId=elb['LoadBalancerName'],
                                    ResourceName=elb['LoadBalancerName'],
                                    ResourceType='elb'))
            if output:
                policy_output = {v['ResourceId']: v for v in output}.values()
                output = policy_output
                return output, evaluated_resources
            else:
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_insecure_ssl_ciphers(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_elb_insecure_ssl_ciphers_protocols(
                'Ciphers')
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_insecure_ssl_protocols(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_elb_insecure_ssl_ciphers_protocols(
                'Protocols')
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_instances_distribution_across_AZs(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                    print(elb_response)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerName=elb['LoadBalancerName'])
                    elb_descriptions = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancer_attributes',
                        operation_args=operation_args,
                        region_name=region)

                    if not (
                            elb_descriptions.get(
                                'LoadBalancerAttributes',
                                {}).get(
                                'CrossZoneLoadBalancing',
                                {}).get('Enabled') and len(
                        elb['AvailabilityZones']) > len(
                        elb['Instances'])):
                        output.append(
                            OrderedDict(
                                ResourceId=elb['LoadBalancerName'],
                                ResourceName=elb['LoadBalancerName'],
                                ResourceType="elb"))

            return output, evaluated_resources

        except Exception as e:
            raise Exception(e.message)

    def aws_elb_security_policy(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_elb_insecure_ssl_ciphers_protocols(
                'Security')
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def common_elbv2_alb(self, check_type):
        output = list()
        evaluated_resources = 0

        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancers')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args = {}
                    operation_args.update(
                        LoadBalancerArn=elb['LoadBalancerArn'])
                    listener_info = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_listeners',
                        operation_args=operation_args,
                        region_name=region)
                    for portal_info in listener_info['Listeners']:
                        if check_type == 'listener_security':
                            if portal_info['Protocol'] != "HTTPS":
                                # Non-Compliant
                                output.append(
                                    OrderedDict(
                                        ResourceId=elb['LoadBalancerArn'],
                                        ResourceName=elb['LoadBalancerArn'],
                                        ResourceType='ELBV2'))
                        elif check_type == 'security_group':
                            if 'Protocol' in portal_info.keys():
                                if portal_info['Protocol'] == 'HTTP' and portal_info['Port'] == int(
                                        80):
                                    operation_args = {}
                                    operation_args.update(
                                        LoadBalancerArns=[elb['LoadBalancerArn']])
                                    load_balancers_response = run_aws_operation(
                                        credentials,
                                        'elbv2',
                                        'describe_load_balancers',
                                        operation_args,
                                        region_name=region,
                                        response_key='LoadBalancers')
                                    for _load_balancer in load_balancers_response:
                                        operation_args = {}
                                        operation_args.update(
                                            GroupIds=_load_balancer['SecurityGroups'])
                                        security_response = run_aws_operation(
                                            credentials,
                                            'ec2',
                                            'describe_security_groups',
                                            operation_args=operation_args,
                                            region_name=region,
                                            response_key='SecurityGroups')
                                        if any(
                                                desc['GroupName'] == 'default' for desc in security_response):
                                            output.append(
                                                OrderedDict(
                                                    ResourceId=elb['DNSName'],
                                                    ResourceName=elb['DNSName'],
                                                    ResourceType='ELBV2'))
                                        else:
                                            for security_group in security_response:
                                                fromport_value = security_group['IpPermissions']
                                                for i in fromport_value:
                                                    fromport = i['FromPort']
                                                    if fromport != 80:
                                                        output.append(
                                                            OrderedDict(
                                                                ResourceId=elb['DNSName'],
                                                                ResourceName=elb['DNSName'],
                                                                ResourceType='ELBV2'))
                        elif check_type == 'security_policy':
                            ssl_compared_value = [
                                'ELBSecurityPolicy-2016-08',
                                'ELBSecurityPolicy-TLS-1-2-Ext-2018-06',
                                'ELBSecurityPolicy-FS-2018-06',
                                'ELBSecurityPolicy-TLS-1-1-2017-01']
                            if 'SslPolicy' in portal_info.keys():
                                if portal_info['SslPolicy']:
                                    if portal_info['SslPolicy'] not in ssl_compared_value:
                                        output.append(
                                            OrderedDict(
                                                ResourceId=elb['LoadBalancerArn'],
                                                ResourceName=elb['LoadBalancerArn'],
                                                ResourceType='ELBV2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_elbv2_alb_listener_security(self):
        output, evaluated_resources = self.common_elbv2_alb(
            'listener_security')
        return output, evaluated_resources

    def aws_elbv2_alb_security_group(self):
        output, evaluated_resources = self.common_elbv2_alb('security_group')
        return output, evaluated_resources

    def aws_elbv2_alb_security_policy(self):
        output, evaluated_resources = self.common_elbv2_alb('security_policy')
        return output, evaluated_resources

    def aws_ec2_enable_hibernation(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ec2_reservations in ec2_instance_response['Reservations']:
                    for ec2_instance_info in ec2_reservations['Instances']:
                        evaluated_resources += 1
                        if ec2_instance_info.get(
                                'HibernationOptions', {}).get('Configured') == False:
                            output.append(
                                OrderedDict(
                                    ResourceId=ec2_instance_info['InstanceId'],
                                    ResourceName=ec2_instance_info['InstanceId'],
                                    ResourceType="EC2"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_ec2_instance_in_auto_scaling_group(self, **kwargs):
        output = list()
        evaluated_resources = 0
        instanceidslist = list()
        auto_scaling_instance_list = list()
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ec2_reservations in ec2_instance_response['Reservations']:
                    for ec2_instance_info in ec2_reservations['Instances']:
                        instanceidslist.append(ec2_instance_info['InstanceId'])
                        evaluated_resources += 1
                        operation_args.update(
                            InstanceIds=[
                                ec2_instance_info['InstanceId'],
                            ]
                        )
                        asg_response = run_aws_operation(
                            credentials,
                            'autoscaling',
                            'describe_auto_scaling_instances',
                            operation_args=operation_args,
                            region_name=region)
                        for asg in asg_response['AutoScalingInstances']:
                            auto_scaling_instance_list.append(
                                asg['InstanceId'])
                    check = all(
                        item in instanceidslist for item in auto_scaling_instance_list)
                    if not check:
                        output.append(
                            OrderedDict(
                                ResourceId=ec2_instance_info['InstanceId'],
                                ResourceName=ec2_instance_info['InstanceId'],
                                ResourceType="EC2"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_elb_internet_facing(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    if elb['Scheme'] == "internet-facing":
                        output.append(
                            OrderedDict(
                                ResourceId=elb['LoadBalancerName'],
                                ResourceName=elb['LoadBalancerName'],
                                ResourceType="elb"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_elbv2_internet_facing(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancers')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    if elb['Scheme'] == "internet-facing":
                        output.append(
                            OrderedDict(
                                ResourceId=elb['LoadBalancerName'],
                                ResourceName=elb['LoadBalancerName'],
                                ResourceType="elb"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_lambda_cross_account_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        credentials = self.execution_args['auth_values']
        sts_client = run_aws_operation(
            credentials, 'sts', 'get_caller_identity')
        account_id = sts_client['Account']
        operation_args.update(FunctionVersion='ALL')
        try:
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    operation_args = {}
                    operation_args.update(
                        FunctionName=function['FunctionName'])
                    try:
                        lambda_policy = run_aws_operation(
                            credentials,
                            'lambda',
                            'get_policy',
                            region_name=region,
                            operation_args=operation_args)
                        policy = json.loads(lambda_policy['Policy'])
                        for statement in policy['Statement']:
                            aws_account_id = statement['Principal']['AWS'].split(
                                ':')[-2]
                            if aws_account_id != account_id:
                                output.append(
                                    OrderedDict(
                                        ResourceId=function['FunctionName'],
                                        ResourceName=function['FunctionName'],
                                        ResourceType='lambda'))
                    except Exception as e:
                        if "ResourceNotFoundError" in str(e):
                            continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_lambda_function_with_admin_privileges(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        credentials = self.execution_args['auth_values']
        operation_args.update(FunctionVersion='ALL')
        try:
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    operation_args = {}
                    operation_args.update(
                        FunctionName=function['FunctionName'])
                    try:
                        operation_args1 = {}
                        policy_response = run_aws_operation(
                            credentials,
                            'lambda',
                            'get_function',
                            region_name=region,
                            operation_args=operation_args)
                        role_value = policy_response['Configuration']['Role']
                        role_name = role_value.split('/')[-1]
                        operation_args1.update(RoleName=role_name)
                        iam_response = run_aws_operation(
                            credentials,
                            'iam',
                            'list_attached_role_policies',
                            operation_args=operation_args1)
                        for policies in iam_response['AttachedPolicies']:
                            operation_args = {}
                            operation_args.update(
                                PolicyArn=policies['PolicyArn'], VersionId='v1')
                            policy_version = run_aws_operation(
                                credentials, 'iam', 'get_policy_version', operation_args=operation_args)
                            for i in policy_version['PolicyVersion']['Document']['Statement']:
                                if i['Effect'] == "Allow" and i['Action'] == "*" and i['Resource'] == "*":
                                    output.append(
                                        OrderedDict(
                                            ResourceId=policies['Arn'],
                                            ResourceName=policies['Arn'],
                                            ResourceType='iam'))
                            list_role_policies = run_aws_operation(
                                credentials, 'iam', 'list_role_policies', operation_args=operation_args1)
                            if list_role_policies['PolicyNames']:
                                operation_args2 = {}
                                operation_args2.update(
                                    RoleName=role_name, PolicyName=list_role_policies['PolicyNames'])
                                iam_inline_policies = run_aws_operation(
                                    credentials,
                                    'iam',
                                    'get_role_policy',
                                    operation_args=operation_args2)
                                print(iam_inline_policies['PolicyDocument'])
                                for policy in iam_inline_policies['PolicyDocument']['Statement']:
                                    if policy['Effect'] == "Allow" and policy['Action'] == "*" and policy[
                                        'Resource'] == "*":
                                        output.append(
                                            OrderedDict(
                                                ResourceId=policies['Arn'],
                                                ResourceName=policies['Arn'],
                                                ResourceType='iam'))
                    except Exception as e:
                        if "Arn" in str(e):
                            continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_lambda_runtime_environment_version(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        version_list = list(map(str.strip, self.execution_args['args']['version_list'].split(',')))
        credentials = self.execution_args['auth_values']
        operation_args.update(FunctionVersion='ALL')
        try:
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    operation_args = {}
                    operation_args.update(
                        FunctionName=function['FunctionName'])
                    try:
                        function_response = run_aws_operation(
                            credentials,
                            'lambda',
                            'get_function_configuration',
                            region_name=region,
                            operation_args=operation_args)
                        if function_response['Runtime'] not in version_list:
                            output.append(
                                OrderedDict(
                                    ResourceId=function['FunctionName'],
                                    ResourceName=function['FunctionName'],
                                    ResourceType='lambda'))
                    except Exception as e:
                        if "ResourceNotFoundError" in str(e):
                            continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_lambda_tracing_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        credentials = self.execution_args['auth_values']
        try:
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    if function.get(
                            'TracingConfig',
                            {}).get('Mode') == "Active":
                        output.append(
                            OrderedDict(
                                ResourceId=function['FunctionName'],
                                ResourceName=function['FunctionName'],
                                ResourceType="lambda"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_s3_authenticated_read_acp(self):
        try:
            violations, count = self.check_s3_operations('READ_ACP')
            return violations, count
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_authenticated_users_read_access(self):
        try:
            violations, count = self.check_s3_operations('READ_ACP')
            return violations, count
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_lifecycle_check(self):
        try:
            violations, count = self.check_s3_operations('LifeCycle_Check')
            return violations, count
        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def generate_snapshot_id_list(snapshots):
        snapshot_ids = []
        for snapshot in snapshots:
            snapshot_ids.append(snapshot.get('SnapshotId', ''))
        return snapshot_ids

    def check_ebs_operation(self, check_type):
        try:
            credentials = self.execution_args.get('auth_values',{})
            output = list()
            operation_args = {}
            evaluated_resources = 0
            regions = [region.get('id')
                       for region in self.execution_args.get('regions',{})]
            for region in regions:
                if check_type == 'Snapshot_encrypted':
                    try:
                        account_snapshot_list = run_aws_operation(credentials, 'ec2', 'describe_snapshots',
                                                                  region_name=region,  # operation_args=operation_args,
                                                                  response_key='Snapshots')
                    except Exception as e:
                        raise Exception(
                            'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                                str(e)))
                    for snapshot in account_snapshot_list:
                        evaluated_resources += 1
                        if not snapshot.get('Encrypted',{}):
                            output.append(
                                OrderedDict(
                                    ResourceId=snapshot['SnapshotId'],
                                    ResourceName=snapshot['SnapshotId'],
                                    ResourceType="EC2"))
                elif check_type == 'Snapshot_Accessible_All':
                    try:
                        account_snapshot_list = run_aws_operation(
                            credentials,
                            'ec2',
                            'describe_snapshots',
                            region_name=region,
                            response_key='Snapshots')
                    except Exception as e:
                        raise Exception(
                            'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                                str(e)))
                    snapshot_id_list = self.generate_snapshot_id_list(
                        account_snapshot_list)
                    for snapshot in snapshot_id_list:
                        operation_args.update(
                            Attribute='createVolumePermission', SnapshotId=snapshot)
                        evaluated_resources += 1
                        try:
                            snapshot_response = run_aws_operation(
                                credentials, 'ec2', 'describe_snapshot_attribute', operation_args, region_name=region)
                        except Exception as e:
                            output.append(
                                OrderedDict(
                                    ResourceId=snapshot,
                                    ResourceName=snapshot,
                                    ResourceType='ec2'))

                        if snapshot_response.get('CreateVolumePermissions',{}):
                            for attr in snapshot_response.get('CreateVolumePermissions',{}):
                                if attr.get('Group',{}) == 'all':
                                    output.append(
                                        OrderedDict(
                                            ResourceId=snapshot,
                                            ResourceName=snapshot,
                                            ResourceType='ec2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ebs_snapshot_encrypted(self):
        try:
            violations, count = self.check_ebs_operation('Snapshot_encrypted')
            return violations, count
        except Exception as e:
            raise Exception(str(e))

    def aws_ebs_snapshot_not_accessible_all(self):
        try:
            violations, count = self.check_ebs_operation('Snapshot_Accessible_All')
            return violations, count
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_iam_db_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_instance_info = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for instance in rds_instance_info:
                    evaluated_resources += 1
                    if not instance.get('IAMDatabaseAuthenticationEnabled'):
                        output.append(
                            OrderedDict(
                                ResourceId=instance['DBInstanceIdentifier'],
                                ResourceName=instance['DBInstanceIdentifier'],
                                ResourceType='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_sg_unrestricted(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_instance_info = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_security_groups',
                        region_name=region,
                        response_key='DBSecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for sg in rds_instance_info:
                    evaluated_resources += 1
                    for item in sg.get('IPRanges', []):
                        if item.get('Status') == 'authorized' and item.get('CIDRIP') == '0.0.0.0/0':
                            output.append(
                                OrderedDict(
                                    ResourceId=sg['DBSecurityGroupArn'],
                                    ResourceName=sg['DBSecurityGroupArn'],
                                    ResourceType='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_access_keys_during_initial_setup(self, **kwargs):
        output, evaluated_resources = self.iam_root_access('iam_initial_access_key')
        return output, evaluated_resources

    def aws_ebs_app_tier_encrpted(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            app_tier_tag = self.execution_args['args'].get('app_tier_tag_key')
            app_tier_tag_value = self.execution_args['args'].get('app_tier_tag_value')
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Filters=[
                        {'Name': "tag:%s" % (app_tier_tag),
                         'Values': [
                             app_tier_tag_value,
                         ]
                         },
                    ], )
                    ebs_volumes_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_volumes',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='Volumes')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ebs_volume in ebs_volumes_response:
                    evaluated_resources += 1
                    if not ebs_volume.get('Encrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=ebs_volume['VolumeId'],
                                ResourceName=ebs_volume['VolumeId'],
                                ResourceType='EBS'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_key_app_tier_kms_customer_master_key_in_use(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            app_tier_tag = self.execution_args['args']["app_tier_tag_key"]
            app_tier_tag_value = self.execution_args['args']["app_tier_tag_value"]
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_response = run_aws_operation(
                        credentials,
                        'kms',
                        'list_keys',
                        region_name=region,
                        response_key='Keys')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for keys in kms_response:
                    operation_args.update(KeyId=keys['KeyId'])
                    evaluated_resources += 1
                    try:
                        app_tier_tag_flag = False
                        key_response = run_aws_operation(
                            credentials,
                            'kms',
                            'list_resource_tags',
                            region_name=region,
                            operation_args=operation_args)
                        if not key_response['Tags']:
                            output.append(
                                OrderedDict(
                                    ResourceId=keys['KeyId'],
                                    ResourceName=keys['KeyId'],
                                    ResourceType='KMS'))
                        else:
                            for tag in key_response['Tags']:
                                if tag['Key'] == app_tier_tag and tag['Value'] == app_tier_tag_value:
                                    app_tier_tag_flag = True
                            if not app_tier_tag_flag:
                                output.append(
                                    OrderedDict(
                                        ResourceId=keys['KeyId'],
                                        ResourceName=keys['KeyId'],
                                        ResourceType='KMS'))
                    except Exception as e:
                        raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_unapproved_users_existence(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            approved_users = list(map(str.strip, self.execution_args['args']['approved_users'].split(',')))
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for users in iam_response:
                evaluated_resources += 1
                if users['UserName'] not in approved_users:
                    output.append(
                        OrderedDict(
                            ResourceId=users['UserName'],
                            ResourceName=users['UserName'],
                            ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_check_for_untrusted_cross_account_iam_roles(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            sts_client = run_aws_operation(
                credentials, 'sts', 'get_caller_identity')
            account_id = sts_client['Account']
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_roles', response_key='Roles')
            for roles in iam_response:
                operation_args.update(RoleName=roles['RoleName'])
                evaluated_resources += 1
                iam_role_response = run_aws_operation(
                    credentials, 'iam', 'get_role', operation_args=operation_args)
                for statement in iam_role_response.get('Role', {}).get('AssumeRolePolicyDocument', {}).get(
                        'Statement', []):
                    if 'AWS' in statement.get('Principal', ''):
                        aws_account_id = statement.get('Principal', {}).get('AWS', ':::').split(':')[-2]
                        if aws_account_id != account_id:
                            output.append(
                                OrderedDict(
                                    ResourceId=roles['RoleName'],
                                    ResourceName=roles['RoleName'],
                                    ResourceType='IAM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_kms_cmk_database_tier_inuse(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            data_tier_tag_key = self.execution_args["data_tier_tag"]
            data_tier_tag_value = self.execution_args["data_tier_tag_value"]
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                database_tier_key = False
                try:
                    kms_response = run_aws_operation(
                        credentials,
                        'kms',
                        'list_keys',
                        region_name=region,
                        response_key='Keys')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))

                for key in kms_response:
                    operation_args.update(KeyId=key['KeyId'])
                    evaluated_resources += 1
                    try:
                        key_resource_tags = run_aws_operation(
                            credentials,
                            'kms',
                            'list_resource_tags',
                            region_name=region,
                            operation_args=operation_args)
                        if key_resource_tags['Tags']:
                            for tag in key_resource_tags['Tags']:
                                if (tag['TagKey'] == data_tier_tag_key and tag['TagValue']
                                        == data_tier_tag_value):
                                    database_tier_key = True
                    except Exception as e:
                        raise Exception(e)
                if not database_tier_key:
                    output.append(
                        OrderedDict(
                            ResourceId=region,
                            ResourceName=region,
                            ResourceType='KMS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_group_with_inline_policies(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            group_response = run_aws_operation(
                credentials, 'iam', 'list_groups', response_key='Groups')
            operation_args = {}
            for group in group_response:
                evaluated_resources += 1
                operation_args.update(GroupName=group['GroupName'])
                group_policies = run_aws_operation(
                    credentials, 'iam', 'list_group_policies', operation_args)
                if len(group_policies['PolicyNames']) > 0:
                    output.append(
                        OrderedDict(
                            ResourceId=group['GroupName'],
                            ResourceName=group['GroupName'],
                            ResourceType='IAM'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_master_and_iam_manager_roles(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        iam_manager = ['iam:AttachRolePolicy', 'iam:CreateGroup',
                       'iam:CreatePolicy', 'iam:CreatePolicyVersion',
                       'iam:CreateRole', 'iam:CreateUser', 'iam:DeleteGroup',
                       'iam:DeletePolicy', 'iam:DeletePolicyVersion', 'iam:DeleteRole',
                       'iam:DeleteRolePolicy', 'iam:DeleteUser', 'iam:PutRolePolicy', 'iam:GetPolicy',
                       'iam:GetPolicyVersion', 'iam:GetRole',
                       'iam:GetRolePolicy', 'iam:GetUser', 'iam:GetUserPolicy', 'iam:ListEntitiesForPolicy',
                       'iam:ListGroupPolicies', 'iam:ListGroups',
                       'iam:ListGroupsForUser', 'iam:ListPolicies', 'iam:ListPoliciesGrantingServiceAccess',
                       'iam:ListPolicyVersions', 'iam:ListRolePolicies',
                       'iam:ListAttachedGroupPolicies', 'iam:ListAttachedRolePolicies', 'iam:ListAttachedUserPolicies',
                       'iam:ListRoles', 'iam:ListUsers',
                       'iam:AddUserToGroup', 'iam:AttachGroupPolicy', 'iam:DeleteGroupPolicy', 'iam:DeleteUserPolicy',
                       'iam:DetachGroupPolicy',
                       'iam:DetachRolePolicy', 'iam:DetachUserPolicy', 'iam:PutGroupPolicy', 'iam:PutUserPolicy',
                       'iam:RemoveUserFromGroup', 'iam:UpdateGroup',
                       'iam:UpdateAssumeRolePolicy', 'iam:UpdateUser']

        iam_master = ['iam:AddUserToGroup', 'iam:AttachGroupPolicy', 'iam:DeleteGroupPolicy', 'iam:DeleteUserPolicy',
                      'iam:DetachGroupPolicy',
                      'iam:DetachRolePolicy', 'iam:DetachUserPolicy', 'iam:PutGroupPolicy', 'iam:PutUserPolicy',
                      'iam:RemoveUserFromGroup', 'iam:UpdateGroup',
                      'iam:UpdateAssumeRolePolicy', 'iam:UpdateUser', 'iam:GetPolicy', 'iam:GetPolicyVersion',
                      'iam:GetRole', 'iam:GetRolePolicy', 'iam:GetUser',
                      'iam:GetUserPolicy', 'iam:ListEntitiesForPolicy', 'iam:ListGroupPolicies', 'iam:ListGroups',
                      'iam:ListGroupsForUser', 'iam:ListPolicies',
                      'iam:ListPoliciesGrantingServiceAccess', 'iam:ListPolicyVersions', 'iam:ListRolePolicies',
                      'iam:ListAttachedGroupPolicies',
                      'iam:ListAttachedRolePolicies', 'iam:ListAttachedUserPolicies', 'iam:ListRoles', 'iam:ListUsers']
        try:
            role_name = self.execution_args['args'].get("role_name")
            credentials = self.execution_args['auth_values']
            operation_args.update(
                RoleName=role_name)
            role_response = run_aws_operation(
                credentials, 'iam', 'get_role', operation_args=operation_args)
            evaluated_resources += 1
            assume_policy_document = role_response.get('Role', {}).get('AssumeRolePolicyDocument', {}).get(
                'Statement', [{}])[0].get('Principal', {}).get('Service')
            if assume_policy_document not in iam_master and assume_policy_document not in iam_manager:
                output.append(
                    OrderedDict(
                        ResourceId=role_name,
                        ResourceName=role_name,
                        ResourceType='IAM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_role_policy_too_permissive(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        operation_args1 = {}
        try:
            credentials = self.execution_args['auth_values']
            start_time = datetime.now()
            roles_response = run_aws_operation(
                credentials, 'iam', 'list_roles', response_key='Roles')
            for role in roles_response:
                evaluated_resources += 1
                operation_args.update(
                    RoleName=role['RoleName'])
                role_policies = run_aws_operation(
                    credentials, 'iam', 'list_role_policies',
                    operation_args=operation_args,
                    response_key='PolicyNames')
                for policy in role_policies:
                    operation_args1.update(
                        RoleName=role['RoleName'],
                        PolicyName=policy)
                    response = run_aws_operation(
                        credentials, 'iam', 'get_role_policy', operation_args=operation_args1)

                    for action in response.get('PolicyDocument', {}).get('Statement', []):
                        if action.get('Action') == "*":
                            output.append(
                                OrderedDict(
                                    ResourceId=policy,
                                    ResourceName=policy,
                                    ResourceType='IAM'))
                        elif isinstance(action['Action'], str):
                            if action['Action'].find("*"):
                                output.append(
                                    OrderedDict(
                                        ResourceId=policy,
                                        ResourceName=policy,
                                        ResourceType='IAM'))
                        elif action['Action'] == "sts:AssumeRole":
                            if action['Principal']['AWS'] == "*":
                                output.append(
                                    OrderedDict(
                                        ResourceId=policy,
                                        ResourceName=policy,
                                        ResourceType='IAM'))
                        elif isinstance(action['Action'], list):
                            if 'iam:PassRole' in action['Action']:
                                output.append(
                                    OrderedDict(
                                        ResourceId=policy,
                                        ResourceName=policy,
                                        ResourceType='IAM'))
                        elif action['Effect'] == "Allow":
                            output.append(
                                OrderedDict(
                                    ResourceId=policy,
                                    ResourceName=policy,
                                    ResourceType='IAM'))
                        if len(output) >= 100 or (datetime.now() - start_time).total_seconds() >= 600:
                            return output, evaluated_resources
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    @staticmethod
    def is_date(string, fuzzy=False):
        """
        Return whether the string can be interpreted as a date.
        :param string: str, string to check for date
        :param fuzzy: bool, ignore unknown tokens in string if True
        """
        try:
            from dateutil.parser import parse
            parse(string, fuzzy=fuzzy)
            return True
        except ValueError:
            return False

    def iam_user_password_expiry(self, input_days):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                get_credential_report_response = run_aws_operation(
                    credentials, 'iam', 'get_credential_report')
            except Exception as err:
                raise err

            if get_credential_report_response:
                content_rows = get_credential_report_response.get("Content").decode('utf-8').split("\n")
                header_rows = content_rows[0]
                header_rows = header_rows.split(",")
                user_index = header_rows.index('user')
                password_last_changed_index = header_rows.index('password_last_changed')
                for col_list in content_rows[1:]:
                    evaluated_resources += 1
                    col = (col_list.split(","))
                    date_string = col[password_last_changed_index].split('+')[0]
                    if self.is_date(date_string):
                        date_object = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S")
                        days_before = (datetime.now() - timedelta(days=input_days))
                        if days_before >= date_object:
                            output.append(
                                OrderedDict(
                                    ResourceId=col[user_index],
                                    ResourceName=col[user_index],
                                    ResourceType='IAM'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_user_password_expiry_45_days(self):
        try:
            output, evaluated_resources = self.iam_user_password_expiry(45)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_user_password_expiry_7_days(self):
        try:
            output, evaluated_resources = self.iam_user_password_expiry(7)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_user_with_password_and_access_keys(self):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(credentials, 'iam', 'list_users')
            operation_args = {}
            for iam in iam_response.get('Users', []):
                evaluated_resources += 1
                operation_args.update(UserName=iam['UserName'])
                iam_user_response = run_aws_operation(credentials, 'iam', 'list_access_keys', operation_args)
                if iam_user_response:
                    try:
                        login_response = run_aws_operation(credentials, 'iam', 'get_login_profile', operation_args)
                        if login_response:
                            output.append(
                                OrderedDict(
                                    ResourceId=iam['UserName'],
                                    ResourceName=iam['UserName'],
                                    ResourceType='IAM'))

                    except Exception as e:
                        output.append(
                            OrderedDict(
                                ResourceId=iam['UserName'],
                                ResourceName=iam['UserName'],
                                ResourceType='IAM'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_users_unauthorized_to_edit_access_policies(self):
        try:
            output = list()
            action_compare = ['iam:CreatePolicy', 'iam:CreatePolicyVersion',
                              'iam:DeleteGroupPolicy', 'iam:DeletePolicy',
                              'iam:DeletePolicyVersion', 'iam:DeleteRolePolicy',
                              'iam:DeleteUserPolicy', 'iam:DetachGroupPolicy',
                              'iam:DetachRolePolicy', 'iam:DetachUserPolicy',
                              'iam:PutGroupPolicy', 'iam:PutRolePolicy',
                              'iam:PutUserPolicy', 'iam:UpdateAssumeRolePolicy',
                              'eks:ListFargateProfiles']
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            statementlist = list()
            iam_response = run_aws_operation(credentials, 'iam', 'list_users')
            operation_args = {}
            for iam in iam_response.get('Users', []):
                evaluated_resources += 1
                operation_args.update(UserName=iam['UserName'])
                response = run_aws_operation(credentials, 'iam', 'list_user_policies', operation_args)

                if response.get('PolicyNames'):
                    policy_document_details_list = []
                    for policy_name in response.get('PolicyNames', []):
                        operation_args_temp = {}
                        operation_args_temp.update(UserName=iam['UserName'], PolicyName=str(policy_name))
                        get_user_policy_details = run_aws_operation(credentials, 'iam', 'get_user_policy',
                                                                    operation_args_temp)
                        policy_document_details_list.append(get_user_policy_details.get('PolicyDocument', [{}]))

                    if any(policy_document_details_list):
                        statement = policy_document_details_list[0].get('Statement')
                        users = iam['UserName']
                        statementlist.append({'users': users, 'statement': statement})

                        for u_response in statementlist:
                            statements = u_response.get('statement', [{}])
                            for action in statements:
                                action_values = action.get('Action')
                                if isinstance(action_values, list):
                                    for action_value in action_values:
                                        if action_value in action_compare:
                                            continue
                                        else:
                                            output.append(
                                                OrderedDict(
                                                    ResourceId=iam['UserName'],
                                                    ResourceName=iam['UserName'],
                                                    ResourceType='IAM'))
                                else:
                                    if action_values in action_compare:
                                        continue
                                    else:
                                        output.append(
                                            OrderedDict(
                                                ResourceId=iam['UserName'],
                                                ResourceName=iam['UserName'],
                                                ResourceType='IAM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_kms_customer_master_key_in_use(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_volumes',
                        region_name=region,
                        response_key='Volumes')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for vm_kmskey in ec2_response:
                    evaluated_resources += 1
                    try:
                        operation_args.update(KeyId=vm_kmskey['KmsKeyId'])
                        kms_list_aliases = run_aws_operation(
                            credentials,
                            'kms',
                            'list_aliases',
                            region_name=region,
                            operation_args=operation_args,
                            response_key='Aliases')
                        for key in kms_list_aliases:
                            if 'alias/aws/ebs' in key.get('AliasName', ''):
                                output.append(
                                    OrderedDict(
                                        ResourceId=vm_kmskey['VolumeId'],
                                        ResourceName=vm_kmskey['VolumeId'],
                                        ResourceType='EC2'))
                    except Exception as e:
                        if 'KmsKeyId' in str(e):
                            continue
                        raise e
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_efs_use_customer_kms_key(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    efs_response = run_aws_operation(
                        credentials,
                        'efs',
                        'describe_file_systems',
                        region_name=region,
                        response_key='FileSystems')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for efs in efs_response:
                    evaluated_resources += 1
                    try:
                        operation_args.update(KeyId=efs['KmsKeyId'])
                        kms_list_aliases = run_aws_operation(
                            credentials,
                            'kms',
                            'list_aliases',
                            region_name=region,
                            operation_args=operation_args,
                            response_key='Aliases')
                        for key in kms_list_aliases:
                            if 'aws/elasticfilesystem' in key['AliasName']:
                                output.append(
                                    OrderedDict(
                                        ResourceId=efs['FileSystemId'],
                                        ResourceName=efs['FileSystemId'],
                                        ResourceType='efs'))
                    except Exception as e:
                        if 'KmsKeyId' in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=efs['FileSystemId'],
                                    ResourceName=efs['FileSystemId'],
                                    ResourceType='efs'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_nat_gateway_in_use(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    vpc_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpcs',
                        region_name=region,
                        response_key='Vpcs')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for vpc in vpc_response:
                    operation_args.update(Filters=[
                        {
                            'Name': 'vpc-id',
                            'Values': [
                                vpc['VpcId'],
                            ]
                        },
                        {
                            'Name': 'state',
                            'Values': [
                                'available',
                            ]
                        }, ])
                    nat_gateway = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_nat_gateways',
                        operation_args=operation_args,
                        region_name=region,
                        response_key='NatGateways')
                    evaluated_resources += 1
                    if nat_gateway:
                        output.append(
                            OrderedDict(
                                ResourceId=vpc['VpcId'],
                                ResourceName=vpc['VpcId'],
                                ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_authenticated_users_write_acp_access(self):
        try:
            violations, count = self.check_s3_operations('WRITE_ACP')
            return violations, count
        except Exception as e:
            raise Exception(str(e))

    def aws_specific_gateway_attached_to_specific_vpc(self, **kwargs):
        output = list()
        vpc_list = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    vpc_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_internet_gateways',
                        region_name=region,
                        response_key='InternetGateways')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for vpc in vpc_response:
                    evaluated_resources += 1
                    for attachment in vpc.get('Attachments', []):
                        vpc_id = attachment.get('VpcId', '')
                        operation_args.update(Filters=[
                            {
                                'Name': 'internet-gateway-id',
                                'Values': [vpc.get('InternetGatewayId', '')]
                            },
                            {
                                'Name': 'attachment.state',
                                'Values': ['available']
                            },
                            {
                                'Name': 'attachment.vpc-id',
                                'Values': [vpc_id]
                            }
                        ])
                        vpc_response = run_aws_operation(
                            credentials,
                            'ec2',
                            'describe_internet_gateways',
                            region_name=region,
                            operation_args=operation_args,
                            response_key='InternetGateways')
                        if vpc_response:
                            output.append(
                                OrderedDict(
                                    ResourceId=vpc['InternetGatewayId'],
                                    ResourceName=vpc['InternetGatewayId'],
                                    ResourceType="VPC"))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_vpc_endpoint_cross_account_access(self):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                response = run_aws_operation(credentials, 'ec2', 'describe_vpc_endpoints', region_name=region,
                                             response_key='VpcEndpoints')
                for res in response:
                    evaluated_resources += 1
                    operation_args.update(Filters=[{'Name': 'vpc-endpoint-id', 'Values': [res['VpcEndpointId'], ]}, ])
                    response_vpc = run_aws_operation(credentials, 'ec2', 'describe_vpc_endpoints', region_name=region,
                                                     operation_args=operation_args)
                    for _vpc in response_vpc['VpcEndpoints']:
                        statement = json.loads(_vpc.get('PolicyDocument', '{}'))
                        principal = statement.get('Statement', [{}])[0].get('Principal')
                        if str(principal) == "*":
                            output.append(OrderedDict(ResourceId=_vpc['VpcId'],
                                                      ResourceName=_vpc['VpcId'],
                                                      ResourceType='VPC'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_vps_naming_conventions(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            REGION_LIST = ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-northeast-1',
                           'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'sa-east-1']
            REGION_CODE = ['ue1', 'uw1', 'uw2', 'ew1', 'ec1', 'an1', 'an2', 'as1', 'as2', 'se1']
            ENV_LIST = ['d', 't', 's', 'p']
            ENV_CODE = ['Dev', 'Prod', 'Stg', 'Prod']
            APP_STACK = ['App', 'Stack', 'Web']

            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    vpc_response = run_aws_operation(credentials, 'ec2', 'describe_vpcs', region_name=region,
                                                     response_key='Vpcs')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for vpcs in vpc_response:
                    evaluated_resources += 1
                    for value in vpcs.get('Tags', []):
                        value['Value'] = value.get('Value', 'NA')
                        if value['Value'].startswith('vpc-'):
                            output.append(OrderedDict(ResourceId=vpcs['VpcId'], ResourceName=vpcs['VpcId'],
                                                      ResourceType='VPC'))
                        elif 'VPC' in value['Value'] or 'vpc' in value['Value']:
                            output.append(OrderedDict(ResourceId=vpcs['VpcId'], ResourceName=vpcs['VpcId'],
                                                      ResourceType='VPC'))
                        elif value['Value'] in REGION_LIST or value['Value'] in REGION_CODE:
                            output.append(OrderedDict(ResourceId=vpcs['VpcId'], ResourceName=vpcs['VpcId'],
                                                      ResourceType='VPC'))
                        elif value['Value'] in ENV_LIST or value['Value'] in ENV_CODE:
                            output.append(OrderedDict(ResourceId=vpcs['VpcId'], ResourceName=vpcs['VpcId'],
                                                      ResourceType='VPC'))
                        elif value['Value'] in APP_STACK:
                            output.append(OrderedDict(ResourceId=vpcs['VpcId'], ResourceName=vpcs['VpcId'],
                                                      ResourceType='VPC'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_vpn_tunnel_redundancy(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            filter_name = self.execution_args['args'].get('filter_name')
            filter_values = self.execution_args['args'].get('filter_values')
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Filters=[
                        {'Name': '%s' % (filter_name),
                         'Values': ['%s' % (filter_values)]},
                    ], )
                    vpn_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpn_connections',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for vpn_connection in vpn_response.get('VpnConnections', []):
                    evaluated_resources += 1
                    for telemetry in vpn_connection.get('VgwTelemetry', []):
                        if telemetry.get('Status') == "DOWN":
                            output.append(
                                OrderedDict(
                                    ResourceId=vpn_connection['VpnConnectionId'],
                                    ResourceName=vpn_connection['VpnConnectionId'],
                                    ResourceType='EC2'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_valid_iam_identity_providers(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            date_condition = datetime(2014, 8, 1, 0, 0)
            credentials = self.execution_args['auth_values']
            saml_providers = run_aws_operation(
                credentials, 'iam', 'list_saml_providers')
            for arn in saml_providers.get('SAMLProviderList', []):
                evaluated_resources += 1
                for arn in saml_providers:
                    if 'CreateDate' in arn:
                        if arn['CreateDate'] < date_condition:
                            output.append(
                                OrderedDict(
                                    ResourceId=arn['Arn'],
                                    ResourceName=arn['Arn'],
                                    ResourceType='IAM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ebs_web_tier_encrpted(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            web_tier_tag = self.execution_args['web_tier_tag_key']
            web_tier_tag_value = self.execution_args['web_tier_tag_value']
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Filters=[
                        {'Name': "tag:%s" % (web_tier_tag),
                         'Values': [
                             web_tier_tag_value,
                         ]
                         },
                    ], )
                    ebs_volumes_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_volumes',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='Volumes')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for ebs_volume in ebs_volumes_response:
                    evaluated_resources += 1
                    if not ebs_volume.get('Encrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=ebs_volume['VolumeId'],
                                ResourceName=ebs_volume['VolumeId'],
                                Resource='ElasticBlockStore'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_cluster_deletion_protection(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_clusters = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_clusters',
                        region_name=region,
                        response_key='DBClusters')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for each_dbcluster in db_clusters:
                    evaluated_resources += 1
                    if not each_dbcluster["DeletionProtection"]:
                        output.append(
                            OrderedDict(
                                DatabaseName=each_dbcluster['DBClusterIdentifier'],
                                ResourceType='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_instance_enable_log_exports(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for dbinstance in rds_response:
                    evaluated_resources += 1
                    if not dbinstance.get("EnabledCloudwatchLogsExports"):
                        output.append(
                            OrderedDict(
                                ResourceId=dbinstance['DBInstanceIdentifier'],
                                ResourceName=dbinstance['DBInstanceIdentifier'],
                                ResourceType='RDS'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_rds_config(self, config):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for info in rds_response:
                    evaluated_resources += 1
                    if not info[config]:
                        output.append(
                            OrderedDict(
                                ResourceId=info['DBInstanceIdentifier'],
                                ResourceName=info['DBInstanceIdentifier'],
                                ResourceType='RDS'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_instance_deletion_protection(self, **kwargs):
        try:
            output, evaluated_resources = self.check_rds_config('DeletionProtection')
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_encrypted_with_kms_customer_master_keys(self):
        output = list()
        evaluated_resources = 0
        master_alias = 'alias/aws/rds'
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_instances = run_aws_operation(credentials, 'rds', 'describe_db_instances', region_name=region,
                                                     response_key='DBInstances')
                    kms_alias = run_aws_operation(credentials, 'kms', 'list_aliases', region_name=region,
                                                  response_key='Aliases')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for each_instance in db_instances:
                    evaluated_resources += 1
                    db_instance_name = each_instance["DBInstanceIdentifier"]
                    if each_instance.get('StorageEncrypted'):
                        is_kms_id_match = False
                        for each_kms_alias in kms_alias:
                            if 'KmsKeyId' in each_kms_alias.keys():
                                key = each_instance['KmsKeyId'].split('key/')[1]
                                if each_kms_alias['TargetKeyId'] == key and master_alias != each_kms_alias['AliasName']:
                                    output.append(
                                        OrderedDict(ResourceId=db_instance_name, ResourceName=db_instance_name,
                                                    ResourceType='RDS'))
                                    is_kms_id_match = True
                                    break
                        if not is_kms_id_match:
                            output.append(OrderedDict(ResourceId=db_instance_name, ResourceName=db_instance_name,
                                                      ResourceType='RDS'))
                    else:
                        output.append(OrderedDict(ResourceId=db_instance_name, ResourceName=db_instance_name,
                                                  ResourceType='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_event_notification(self):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                evaluated_resources += 1
                try:
                    rds_event_metadata = run_aws_operation(credentials, 'rds', 'describe_event_subscriptions',
                                                           region_name=region,
                                                           response_key='EventSubscriptionsList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                if not rds_event_metadata:
                    output.append(OrderedDict(ResourceId=service_account_id, ResourceName=service_account_id,
                                              ResourceType='RDS'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def common_rds_describe_db_instances_fun(self, check_type):
        output = list()
        evaluated_resources = 0
        master_username = 'admin'
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_instances = run_aws_operation(credentials, 'rds', 'describe_db_instances',
                                                      region_name=region,
                                                      response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                if rds_instances:
                    for each_instance in rds_instances:
                        evaluated_resources += 1
                        if check_type == 'masteruser':
                            rds_idenitifier = each_instance['DBInstanceIdentifier']
                            if each_instance['MasterUsername'] != master_username:
                                output.append(OrderedDict(ResourceId=rds_idenitifier,
                                                          ResourceName=rds_idenitifier,
                                                          ResourceType='RDS'))
                        elif check_type == 'sufficient_backup':
                            db_name = each_instance["DBInstanceIdentifier"]
                            backup_retention_period = each_instance["BackupRetentionPeriod"]
                            if backup_retention_period < 7:
                                output.append(OrderedDict(ResourceId=db_name,
                                                          ResourceName=db_name,
                                                          ResourceType='RDS'))
                        elif check_type == 'version_upgrade':
                            db_identifier = each_instance['DBInstanceIdentifier']
                            auto_minor_version_upgrade = each_instance['AutoMinorVersionUpgrade']
                            if not auto_minor_version_upgrade:
                                output.append(OrderedDict(ResourceId=db_identifier,
                                                          ResourceName=db_identifier,
                                                          ResourceType='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_master_username(self, **kwargs):
        output, evaluated_resources = self.common_rds_describe_db_instances_fun('masteruser')
        return output, evaluated_resources

    def aws_rds_sufficient_backup_retention_period(self, **kwargs):
        output, evaluated_resources = self.common_rds_describe_db_instances_fun('sufficient_backup')
        return output, evaluated_resources

    def aws_rds_security_groups_events_subscriptions(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            security_group_event_subscription = False
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_event_subscriptions',
                        region_name=region,
                        response_key='EventSubscriptionsList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for info in rds_response:
                    evaluated_resources += 1
                    if info['SourceType'] == 'db-security-group':
                        security_group_event_subscription = True
                if not security_group_event_subscription:
                    output.append(
                        OrderedDict(
                            ResourceId=info['CustomerAwsId'],
                            ResourceName=info['CustomerAwsId'],
                            ResourceType='rds'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_netbios_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            any_conditional = [
                                True if security_group_ip_permissions.get('FromPort') and
                                        security_group_ip_permissions.get('ToPort') == 137 else False,
                                True if security_group_ip_permissions.get('FromPort') and
                                        security_group_ip_permissions.get('ToPort') == 138 else False,
                                True if security_group_ip_permissions.get('FromPort') and
                                        security_group_ip_permissions.get('ToPort') == 139 else False
                            ]
                            if any(any_conditional):
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_oracle_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            if security_group_ip_permissions.get(
                                    'FromPort') == 1521 and security_group_ip_permissions.get('ToPort') == 1521:
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_outbound_access_on_all_port(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    for security_group_outbound in security_group.get('IpPermissionsEgress'):
                        for security_outbound_cidr in security_group_outbound.get('IpRanges'):
                            if security_outbound_cidr.get('CidrIp') == '0.0.0.0/0':
                                output.append(
                                    OrderedDict(
                                        ResourceId=security_group.get('GroupId'),
                                        ResourceName=security_group.get('GroupId'),
                                        ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_postgres_sql_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            if security_group_ip_permissions.get(
                                    'FromPort') == 5432 and security_group_ip_permissions.get('ToPort') == 5432:
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_rdp_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            if security_group_ip_permissions.get(
                                    'FromPort') == 3389 and security_group_ip_permissions.get('ToPort') == 3389:
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_rpc_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups.get('SecurityGroups'):
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ip_permissions in security_group.get('IpPermissions'):
                        if security_group_ip_permissions.get('IpProtocol') != '-1':
                            if security_group_ip_permissions.get(
                                    'FromPort') == 135 and security_group_ip_permissions.get('ToPort') == 135:
                                for ip_address in security_group_ip_permissions.get('IpRanges'):
                                    if ip_address.get('CidrIp') == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ip_permissions.get('Ipv6Ranges'):
                                    if ip_address.get('CidrIpv6') == '::/0':
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group.get('GroupId'),
                                ResourceName=security_group.get('GroupId'),
                                ResourceType="Security_Groups"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def iam_root_access(self, check_type):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get("service_account_name")
            credentials = self.execution_args['auth_values']
            content = run_aws_operation(
                credentials, 'iam', 'get_credential_report').get('Content', b'').decode()
            file_content = StringIO(content)
            csv_data = csv.reader(file_content, delimiter=",")
            try:
                next(csv_data)
            except StopIteration:
                return output, evaluated_resources
            for data in csv_data:
                evaluated_resources += 1
                try:
                    if check_type == 'access_key_active':
                        if data[0] == '<root_account>' and (data[8] == 'true' or data[13] == 'true'):
                            output.append(OrderedDict(ResourceId=data[0], ResourceName=data[0], Resource='iam',
                                                      ServiceAccountId=service_account_id,
                                                      ServiceAccountName=service_account_name))
                    elif check_type == 'mfa_active':
                        if data[0] == '<root_account>' and data[7] == 'false':
                            output.append(OrderedDict(ResourceId=data[0], ResourceName=data[0], Resource='iam',
                                                      ServiceAccountId=service_account_id,
                                                      ServiceAccountName=service_account_name))
                    elif check_type == 'date':
                        password_last_changed = data[5]
                        try:
                            date_object = datetime.strptime(password_last_changed, "%Y-%m-%dT%H:%M:%S")
                            days_before = (datetime.now() - timedelta(days=30))
                            if not days_before >= date_object:
                                # Non-Compliant
                                output.append(OrderedDict(ResourceId=data[0], ResourceName=data[0], Resource='iam',
                                                          ServiceAccountId=service_account_id,
                                                          ServiceAccountName=service_account_name))
                        except ValueError as e:
                            # Compliant
                            output.append(OrderedDict(ResourceId=data[0], ResourceName=data[0], Resource='iam',
                                                      ServiceAccountId=service_account_id,
                                                      ServiceAccountName=service_account_name))
                            continue
                except Exception as e:
                    continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_iam_user_password_expiry_30_days(self, **kwargs):
        output, evaluated_resources = self.iam_root_access('date')
        return output, evaluated_resources

    def aws_audit_iam_users_with_admin_privileges(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            user_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for user in user_response:
                evaluated_resources += 1
                operation_args = dict(UserName=user.get('UserName', 'NA'))
                policy_response = run_aws_operation(
                    credentials, 'iam', 'list_attached_user_policies', operation_args, response_key='AttachedPolicies')
                if any(tmp_policy.get('PolicyName') == 'AdministratorAccess' for tmp_policy in policy_response):
                    output.append(
                        OrderedDict(
                            ResourceId=user.get('UserName'),
                            ResourceName=user.get('UserName'),
                            ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_inactive_iam_user(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            user_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for user in user_response:
                evaluated_resources += 1
                operation_args = dict(UserName=user.get('UserName', 'NA'))
                iam_user_response = run_aws_operation(
                    credentials, 'iam', 'list_access_keys',
                    operation_args=operation_args,
                    response_key='AccessKeyMetadata')
                for access_key_usage in iam_user_response:
                    if access_key_usage.get('Status') == 'Inactive':
                        output.append(
                            OrderedDict(
                                ResourceId=user.get('UserName'),
                                ResourceName=user.get('UserName'),
                                ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_s3_bucket_mfa_delete_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(
                credentials, 's3', 'list_buckets')
            for bucket in s3_buckets['Buckets']:
                operation_args = dict(Bucket=bucket.get('Name'))
                evaluated_resources += 1
                s3_bucket_mfa_delete_enabled = run_aws_operation(
                    credentials, 's3', 'get_bucket_versioning', operation_args)
                if s3_bucket_mfa_delete_enabled.get('Status') != 'Enabled':
                    output.append(
                        OrderedDict(
                            ResourceId=bucket.get('Name'),
                            ResourceName=bucket.get('Name'),
                            Resource='Buckets',
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ssh_public_keys_rotated_30_days(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_cmn_audit_ssh_public_keys_rotated_by_days(days=30)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_ssh_public_keys_rotated(self, **kwargs):
        output = list()
        evaluated_resources = 0
        statement_list = list()
        ssh_public_key_id_list = list()
        today = datetime.now().date()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            days_limit = self.execution_args['args'].get('days_limit')
            response = run_aws_operation(credentials, 'iam', 'list_users', response_key="Users")
            for users_list in response:
                users = users_list['UserName']
                users_args = {'UserName': users}
                evaluated_resources += 1
                ssh_public_key_response = run_aws_operation(credentials, 'iam', 'list_ssh_public_keys',
                                                            operation_args=users_args)
                statement_list.append(ssh_public_key_response)
                if statement_list:
                    for response in statement_list:
                        ssh_key_details = response['SSHPublicKeys']
                        if ssh_key_details:
                            for ssh_key in ssh_key_details:
                                status = ssh_key['Status']
                                if status == 'Active':
                                    upload_date = parse(ssh_key['UploadDate'])
                                    days_bet = str(today - upload_date.date())
                                    if 'days' in days_bet:
                                        days_int = int(days_bet.split('d')[0])
                                    else:
                                        days_int = 0
                                    if days_int > days_limit:
                                        ssh_public_key_id = ssh_key['SSHPublicKeyId']
                                        if ssh_public_key_id not in ssh_public_key_id_list:
                                            ssh_public_key_id_list.append(ssh_public_key_id)
                                            output.append(
                                                OrderedDict(
                                                    ResourceId=ssh_key.get('SSHPublicKeyId', "NA"),
                                                    ResourceName=ssh_key.get('UserName', "NA"),
                                                    Resource="IAM_Users",
                                                    ServiceAccountId=service_account_id,
                                                    ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ssh_public_keys_rotated_45_days(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_cmn_audit_ssh_public_keys_rotated_by_days(days=45)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ssh_public_keys_rotated_90_days(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_cmn_audit_ssh_public_keys_rotated_by_days(days=90)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ec2_ebs_encryption_by_default(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ebs_volumes_response = run_aws_operation(
                        credentials, 'ec2', 'describe_volumes', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                ebs_volume_list = ebs_volumes_response.get('Volumes')
                for ebs_Volume in ebs_volume_list:
                    evaluated_resources += 1
                    if not ebs_Volume.get('Encrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=ebs_Volume.get('VolumeId'),
                                ResourceName=ebs_Volume.get('VolumeId'),
                                Resource='Volumes',
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ec2_stopped_instance(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials, 'ec2', 'describe_instances', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ec2_reservations in ec2_instance_response.get('Reservations'):
                    for ec2_instance_info in ec2_reservations.get('Instances'):
                        evaluated_resources += 1
                        if ec2_instance_info.get('State', {}).get('Name') != 'running':
                            output.append(
                                OrderedDict(
                                    ResourceId=ec2_instance_info.get('InstanceId'),
                                    ResourceName=ec2_instance_info.get('InstanceId'),
                                    ResourceType="EC2"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_s3_account_level_public_access_blocks(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(
                credentials, 's3', 'list_buckets')
            for bucket in s3_buckets.get('Buckets'):
                operation_args = dict(Bucket=bucket.get('Name'))
                evaluated_resources += 1
                s3_bucket_acl = run_aws_operation(
                    credentials, 's3', 'get_bucket_acl', operation_args)
                for s3_bucket_acl_grant in s3_bucket_acl.get('Grants'):
                    if s3_bucket_acl_grant.get('Permission') == "WRITE_ACP" and \
                            s3_bucket_acl_grant.get('Grantee', {}).get('URI') == \
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                        output.append(
                            OrderedDict(
                                ResourceId=bucket.get('Name'),
                                ResourceName=bucket.get('Name'),
                                ResourceType='S3'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ssl_tls_certificate_expire_30_days(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_cmn_audit_ssl_tls_certificate_expire_by_days(expiry_days=30)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ssl_tls_certificate_expire_45_days(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_cmn_audit_ssl_tls_certificate_expire_by_days(expiry_days=45)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ssl_tls_certificate_expire_7_days(self, **kwargs):
        try:
            output, evaluated_resources = self.aws_cmn_audit_ssl_tls_certificate_expire_by_days(expiry_days=7)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_s3_bucket_open_to_the_world_with_no_encryption(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(
                credentials, 's3', 'list_buckets')
            operation_args = {}
            for bucket in s3_buckets.get('Buckets'):
                operation_args.update(Bucket=bucket.get('Name'))
                evaluated_resources += 1
                try:
                    bucket_encryption = run_aws_operation(
                        credentials, 's3', 'get_bucket_encryption', operation_args)
                    _ = bucket_encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules')
                    if not bucket_encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules'):
                        output.append(
                            OrderedDict(
                                ResourceId=bucket.get('Name'),
                                ResourceName=bucket.get('Name'),
                                Resource='Buckets',
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
                except Exception as e:
                    if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                        output.append(
                            OrderedDict(
                                ResourceId=bucket.get('Name'),
                                ResourceName=bucket.get('Name'),
                                Resource='Buckets',
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unattached_ebs_volumes(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            operation_args.update(Filters=[{'Name': 'status', 'Values': ['available', ]}, ])
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ebs_response = run_aws_operation(
                        credentials, 'ec2', 'describe_volumes', operation_args, region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for volume in ebs_response.get('Volumes'):
                    evaluated_resources += 1
                    if volume.get('VolumeId'):
                        output.append(OrderedDict(
                            ResourceId=volume.get('VolumeId'),
                            ResourceName=volume.get('VolumeId'),
                            Resource='Volumes',
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_mq_is_publicly_accessible(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    mq_response = run_aws_operation(
                        credentials, 'mq', 'list_brokers', region_name=region, response_key='BrokerSummaries')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for mq in mq_response:
                    operation_args.update(BrokerId=mq.get('BrokerId'))
                    evaluated_resources += 1
                    try:
                        response = run_aws_operation(
                            credentials, 'mq', 'describe_broker', operation_args, region_name=region)
                    except Exception as e:
                        raise Exception(
                            'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                                str(e)))
                    if response.get('PubliclyAccessible'):
                        output.append(OrderedDict(
                            ResourceId=mq.get('BrokerId'),
                            ResourceName=mq.get('BrokerId'),
                            Resource='MQ',
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_redshift_instances_not_encrypted(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    response = run_aws_operation(
                        credentials, 'redshift', 'describe_clusters', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster in response.get('Clusters'):
                    evaluated_resources += 1
                    if not cluster['Encrypted']:
                        OrderedDict(
                            ResourceId=cluster.get('ClusterIdentifier'),
                            ResourceName=cluster.get('ClusterIdentifier'),
                            Resource='Clusters',
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name'])
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_s3_bucket_get_global_bucket_policy(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            operation_args = {}
            for bucket in s3_buckets.get('Buckets'):
                operation_args.update(Bucket=bucket.get('Name'))
                evaluated_resources += 1
                try:
                    _ = run_aws_operation(
                        credentials, 's3', 'get_bucket_policy', operation_args)
                except Exception as e:
                    print(e)
                    if 'NoSuchBucketPolicy' in str(e):
                        output.append(
                            OrderedDict(
                                ResourceId=bucket.get('Name'),
                                ResourceName=bucket.get('Name'),
                                Resource='Buckets'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ec2_publicly_shared_ami(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            operation_args.update(Owners=['self', ])
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_response = run_aws_operation(
                        credentials, 'ec2', 'describe_images', operation_args, region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for images in ec2_response.get('Images'):
                    evaluated_resources += 1
                    if images.get('Public'):
                        output.append(OrderedDict(
                            ResourceId=images.get('ImageId'),
                            ResourceName=images.get('ImageId'),
                            Resource='Instances',
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_rds_instance_not_in_public_subnet(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials, 'rds', 'describe_db_instances', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for db_instance in rds_response.get('DBInstances'):
                    evaluated_resources += 1
                    for subnets in db_instance.get('DBSubnetGroup', {}).get('Subnets'):
                        operation_args.update(
                            Filters=[
                                {'Name': 'association.subnet-id', 'Values': [subnets.get('SubnetIdentifier'), ]}, ])
                        try:
                            router_response = run_aws_operation(
                                credentials, 'ec2', 'describe_route_tables', operation_args, region_name=region)
                        except Exception as e:
                            raise Exception(
                                'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                                    str(e)))
                        for route in router_response.get('RouteTables'):
                            for ing in route.get('Routes'):
                                if ing.get.get('GatewayId') and ing.get('DestinationCidrBlock') == '0.0.0.0/0':
                                    output.append(OrderedDict(
                                        ResourceId=db_instance.get('DBInstanceIdentifier'),
                                        ResourceName=db_instance.get('DBInstanceIdentifier'),
                                        Resource='RDS',
                                        ServiceAccountId=service_account_id,
                                        ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_rds_copy_tags_to_snapshots(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials, 'rds', 'describe_db_instances', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for db_instance in rds_response['DBInstances']:
                    evaluated_resources += 1
                    if not db_instance.get('CopyTagsToSnapshot'):
                        output.append(OrderedDict(
                            ResourceId=db_instance['DBInstanceIdentifier'],
                            ResourceName=db_instance['DBInstanceIdentifier'],
                            Resource='RDS',
                            ServiceAccountId=service_account_id,
                            ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_acm_certificates_with_wildcard_domain_names(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            operation_args.update(CertificateStatuses=['ISSUED'])
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    acm_response = run_aws_operation(
                        credentials, 'acm', 'list_certificates', operation_args, region_name=region,
                        response_key='CertificateSummaryList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for acm in acm_response:
                    evaluated_resources += 1
                    if '*' in acm.get('DomainName'):
                        output.append(OrderedDict(
                            ResourceId=acm.get('CertificateArn').split('/')[1],
                            ResourceName=acm.get('CertificateArn').split('/')[1],
                            ResourceType='Certificate_Manager',
                            DomainName=acm.get('DomainName', '')
                        ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_elasticsearch_domain_publicly_accessible(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for es_domain in es_response.get('DomainNames'):
                    operation_args.update(DomainName=es_domain.get('DomainName'))
                    evaluated_resources += 1
                    try:
                        response = run_aws_operation(credentials, 'es', 'describe_elasticsearch_domain',
                                                     operation_args, region_name=region)
                    except Exception as e:
                        raise Exception(
                            'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                                str(e)))
                    policy = json.loads(response.get('DomainStatus', {}).get('AccessPolicies'))
                    for statement in policy.get('Statement'):
                        if 'AWS' in statement.get('Principal').keys() and "*" in statement.get('Principal').values():
                            output.append(OrderedDict(
                                ResourceId=es_domain.get('DomainName'),
                                ResourceName=es_domain.get('DomainName'),
                                Resource='ElasticSearch',
                                ServiceAccountId=service_account_id,
                                ServiceAccountName=self.execution_args['service_account_name']))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def audit_cost_for_the_gcp_resource_type_to_scale_anomaly(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            master_account_auth_values = self.execution_args.get("master_account_auth_values", {})
            percentage_to_check = int(self.execution_args['args'].get("percentage_to_check", "0"))
            account_project = credentials.get("project_id")
            curr_date_data_frame = pd.DataFrame()
            last_month_data_frame = pd.DataFrame()
            final_data_frame = pd.DataFrame()
            if credentials.get("account_type") == "linked_project_account":
                credentials = master_account_auth_values
            billing_account_name = credentials.get("billing_account")
            project_id = credentials.get("project_id")
            primary_data_set_id = credentials.get("data_set_id")
            primary_table_name = (project_id + "." + primary_data_set_id + ".gcp_billing_export_v1_" +
                                  billing_account_name.replace("-", "_"))
            query = GCPUtils.gcp_backfill_account_query % (primary_table_name, account_project)
            if credentials.get("protocol") == GCPUtils.SERVICE_ACCOUNT:
                result_for_prev_month = run_big_query_job(credentials, query)
                query_for_curr_day = GCPUtils.gcp_find_query_for_day % (primary_table_name, account_project)
                result_for_curr_day = run_big_query_job(credentials, query_for_curr_day)
                if not result_for_curr_day.total_rows:
                    return output, 0
                else:
                    curr_date_data_frame = result_for_curr_day.to_dataframe()
                if not result_for_prev_month.total_rows:
                    return output, 0
                else:
                    last_month_data_frame = result_for_prev_month.to_dataframe()
            else:
                result_for_prev_month, prev_schema_list = run_bigquery_job_for_oauth2_type(credentials, query,
                                                                                           primary_data_set_id)
                query_for_curr_day = GCPUtils.gcp_find_query_for_day % (primary_table_name, account_project)
                result_for_curr_day, curr_schema_list = run_bigquery_job_for_oauth2_type(credentials,
                                                                                         query_for_curr_day,
                                                                                         primary_data_set_id)
                if not result_for_curr_day:
                    return output, 0
                else:
                    curr_date_data_frame = pd.DataFrame(result_for_curr_day, columns=curr_schema_list)
                if not result_for_prev_month:
                    return output, 0
                else:
                    last_month_data_frame = pd.DataFrame(result_for_prev_month, columns=prev_schema_list)
            final_data_frame = pd.merge(curr_date_data_frame, last_month_data_frame, on=["resource_id"],
                                        suffixes=('', '_monthly'), how='outer')
            if not final_data_frame.empty:
                final_data_frame["cost_difference_between_attributes"] = \
                    final_data_frame["cost_for_day"] - final_data_frame["average_cost_for_month"]
                final_data_frame = final_data_frame.loc[(final_data_frame["cost_difference_between_attributes"] > 0)]
                if not final_data_frame.empty:
                    final_data_frame["ChangePercent"] = (abs(final_data_frame["cost_difference_between_attributes"]) /
                                                         final_data_frame["cost_for_day"]) * 100
                    final_data_frame = final_data_frame.loc[
                        (final_data_frame["ChangePercent"] > percentage_to_check)]
                    if not final_data_frame.empty:
                        final_data_frame.rename(columns={
                            "resource_id": "ResourceId",
                            "resource_id_monthly": "ResourceName",
                            "cost_for_day": "DayForCost",
                            "average_cost_for_month": "AvgDailyCost"
                        }, inplace=True)
                        final_data_frame["ResourceName"] = final_data_frame["ResourceId"]
                        final_data_frame["Resource"] = final_data_frame["ResourceName"]
                        final_data_frame["ServiceAccountId"] = service_account_id
                        final_data_frame["ServiceAccountName"] = self.execution_args['service_account_name']
                        output = final_data_frame.to_dict(orient='records')
            return output, len(output)
        except Exception as e:
            raise Exception(str(e))

    def check_elb_listeners_https_ssl(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    response_list = run_aws_operation(credentials, 'elb', 'describe_load_balancers', region_name=region,
                                                      response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for response in response_list:
                    evaluated_resources += 1
                    for listener in response['ListenerDescriptions']:
                        try:
                            protocol = listener.get('Listener', {}).get('Protocol').lower()
                            if protocol not in ['https', 'ssl']:
                                output.append(
                                    OrderedDict(ResourceId=response['LoadBalancerName'],
                                                ResourceName=response['DNSName'],
                                                ResourceType="Load_Balancers",
                                                Region=region))
                        except Exception as e:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_whether_ecs_is_configured_with_cloud_watch(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ecs_response = run_aws_operation(
                        credentials,
                        'ecs',
                        'list_clusters',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster_arn in ecs_response.get('clusterArns'):
                    operation_args = dict(clusters=[cluster_arn], include=['SETTINGS'])
                    evaluated_resources += 1
                    ecs_response = run_aws_operation(
                        credentials,
                        'ecs',
                        'describe_clusters',
                        operation_args,
                        region_name=region)
                    for cluster in ecs_response.get('clusters'):
                        for setting in cluster.get('settings'):
                            if setting.get('name') == 'containerInsights' and setting.get('value') == 'disabled':
                                output.append(OrderedDict(
                                    ResourceId=cluster_arn,
                                    ResourceName=cluster_arn,
                                    ResourceType='ECS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def configure_your_tasks_to_use_the_aws_vpc_network_mode(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ecs_response = run_aws_operation(
                        credentials,
                        'ecs',
                        'list_task_definitions',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ecs_task_arn in ecs_response.get('taskDefinitionArns'):
                    operation_args = dict(taskDefinition=ecs_task_arn)
                    evaluated_resources += 1
                    ecs_response = run_aws_operation(
                        credentials,
                        'ecs',
                        'describe_task_definition',
                        operation_args,
                        region_name=region)
                    if ecs_response.get('taskDefinition', {}).get('networkMode') != 'awsvpc':
                        output.append(OrderedDict(
                            ResourceId=ecs_task_arn,
                            ResourceName=ecs_task_arn,
                            ResourceType='ECS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_aws_elasticache_cluster_are_not_using_the_default_ports(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec_response = run_aws_operation(
                        credentials,
                        'elasticache',
                        'describe_cache_clusters',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster in ec_response['CacheClusters']:
                    evaluated_resources += 1
                    if cluster.get('Engine') == 'memcached':
                        if cluster.get('ConfigurationEndpoint', {}).get('Port') == 11211:
                            output.append(OrderedDict(
                                ResourceId=cluster['CacheClusterId'],
                                ResourceName=cluster['CacheClusterId'],
                                ResourceType='ElastiCache'))
                    if cluster.get('Engine') == 'redis':
                        operation_args = dict(ReplicationGroupId=cluster.get('ReplicationGroupId'))
                        rep_response = run_aws_operation(
                            credentials,
                            'elasticache',
                            'describe_replication_groups',
                            operation_args,
                            region_name=region)
                        for info in rep_response.get('ReplicationGroups'):
                            if info.get('ConfigurationEndpoint', {}).get('Port') == 6379:
                                output.append(OrderedDict(
                                    ResourceId=cluster['CacheClusterId'],
                                    ResourceName=cluster['CacheClusterId'],
                                    ResourceType='ElastiCache'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_aws_elasticache_cluster_are_deployed_into_a_virtual_private_cloud(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec_response = run_aws_operation(
                        credentials,
                        'elasticache',
                        'describe_cache_clusters',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster in ec_response.get('CacheClusters'):
                    evaluated_resources += 1
                    if not cluster.get('CacheSubnetGroupName'):
                        output.append(OrderedDict(
                            ResourceId=cluster.get('CacheClusterId'),
                            ResourceName=cluster.get('CacheClusterId'),
                            ResourceType='ElastiCache'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_that_all_your_aws_elasticache_cluster_cache_nodes_are_of_given_types(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            valid_instance_type = self.execution_args['args'].get('valid_instance_type')
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec_response = run_aws_operation(
                        credentials,
                        'elasticache',
                        'describe_cache_clusters',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster in ec_response.get('CacheClusters'):
                    evaluated_resources += 1
                    if cluster.get('CacheNodeType') not in valid_instance_type.split(','):
                        output.append(OrderedDict(
                            ResourceId=cluster['CacheClusterId'],
                            ResourceName=cluster['CacheClusterId'],
                            ResourceType='ElastiCache'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_that_the_latest_version_of_redis_memcached_is_used_for_elasticache_cluster(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            memcached_version = self.execution_args['args'].get('memcached_version')
            redis_version = self.execution_args['redis_version']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec_response = run_aws_operation(
                        credentials,
                        'elasticache',
                        'describe_cache_clusters',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster in ec_response['CacheClusters']:
                    evaluated_resources += 1
                    if cluster.get('Engine') == 'memcached' and cluster.get('EngineVersion') != memcached_version:
                        output.append(OrderedDict(
                            ResourceId=cluster['CacheClusterId'],
                            ResourceName=cluster['CacheClusterId'],
                            ResourceType='ElastiCache'))
                    if cluster.get('Engine') == 'redis' and cluster.get('EngineVersion') != redis_version:
                        output.append(OrderedDict(
                            ResourceId=cluster['CacheClusterId'],
                            ResourceName=cluster['CacheClusterId'],
                            ResourceType='ElastiCache'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_intransit_and_atrest_encryption_is_enabled_for_aws_elasticache(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec_response = run_aws_operation(
                        credentials,
                        'elasticache',
                        'describe_cache_clusters',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster in ec_response.get('CacheClusters'):
                    evaluated_resources += 1
                    operation_args = dict((cluster['ReplicationGroupId']))
                    if cluster.get('Engine') == 'redis':
                        rep_response = run_aws_operation(
                            credentials,
                            'elasticache',
                            'describe_replication_groups',
                            operation_args,
                            region_name=region)
                        for info in rep_response.get('ReplicationGroups'):
                            if not info['AtRestEncryptionEnabled'] and not info['TransitEncryptionEnabled']:
                                output.append(OrderedDict(
                                    ResourceId=cluster['CacheClusterId'],
                                    ResourceName=cluster['CacheClusterId'],
                                    ResourceType='ElastiCache'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_aws_elasticache_redis_clusters_have_the_multi_az_feature_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec_response = run_aws_operation(
                        credentials,
                        'elasticache',
                        'describe_replication_groups',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for replication in ec_response.get('ReplicationGroups'):
                    evaluated_resources += 1
                    if replication.get('AutomaticFailover') == 'disabled':
                        output.append(OrderedDict(
                            ResourceId=replication.get('ReplicationGroupId'),
                            ResourceName=replication.get('ReplicationGroupId'),
                            ResourceType='ElastiCache'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ebs_snapshot_public_restorable_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        operation_args1 = {}
        try:
            service_account_id = self.execution_args['service_account_id']
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Filters=[{'Name': 'status', 'Values': [
                        'completed', ]}, ], OwnerIds=[service_account_id, ])
                    ebs_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_snapshots',
                        region_name=region,
                        response_key='Snapshots',
                        operation_args=operation_args)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for snapshots in ebs_response:
                    operation_args1.update(
                        Attribute='createVolumePermission',
                        SnapshotId=snapshots['SnapshotId'])
                    evaluated_resources += 1
                    snapshot_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_snapshot_attribute',
                        region_name=region,
                        operation_args=operation_args1)
                    if snapshot_response['CreateVolumePermissions']:
                        for result in snapshot_response['CreateVolumePermissions']:
                            for key, value in result.items():
                                if key == 'Group' and value == 'all':
                                    output.append(
                                        OrderedDict(
                                            ResourceId=snapshots['SnapshotId'],
                                            ResourceName=snapshots['SnapshotId'],
                                            Resource='ec2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elbv2_access_log(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancers')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerArn=elb['LoadBalancerArn'])
                    elb_log_info = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancer_attributes',
                        operation_args,
                        region_name=region)
                    for logging_info in elb_log_info['Attributes']:
                        if logging_info['Key'] == 'access_logs.s3.enabled' and logging_info['Value'] == 'false':
                            # Non-Compliant
                            s = 1
                        else:
                            # Compliant
                            output.append(
                                OrderedDict(
                                    ResourceId=elb['LoadBalancerName'],
                                    ResourceName=elb['LoadBalancerName'],
                                    ResourceType="ELB"))
            if output:
                policy_output = {v['ResourceId']: v for v in output}.values()
                output = policy_output
                return output, evaluated_resources
            else:
                return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_network_load_balancer_security_policy(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        policy_list = [
            'ELBSecurityPolicy-2016-08',
            'ELBSecurityPolicy-TLS-1-1-2017-01',
            'ELBSecurityPolicy-FS-2018-06',
            'ELBSecurityPolicy-TLS-1-2-Ext-2018-06']
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancers')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerArn=elb['LoadBalancerArn'])
                    elb_listener_info = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_listeners',
                        operation_args=operation_args,
                        response_key='Listeners')
                    for elb_listener in elb_listener_info:
                        if not (
                                'SslPolicy' in elb_listener and elb_listener['SslPolicy'] in policy_list):
                            output.append(
                                OrderedDict(
                                    ResourceId=elb['LoadBalancerName'],
                                    ResourceName=elb['LoadBalancerName'],
                                    ResourceType="elb"))
            return output, evaluated_resources

        except Exception as e:
            raise Exception(e.message)

    def aws_webtier_elb_listener_security(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            web_tier_tag_key = self.execution_args.get("web_tier_tag")["key"]
            web_tier_tag_value = self.execution_args.get("web_tier_tag")[
                "value"]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))

                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerNames=[elb['LoadBalancerName']])
                    tag_info = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_tags',
                        operation_args=operation_args)
                    for elb_tag in tag_info['TagDescriptions']:
                        for tag in elb_tag['Tags']:
                            if tag['Value'] == web_tier_tag_value and tag['Key'] == web_tier_tag_key:
                                if elb['ListenerDescriptions']:
                                    for listener_descriptions in elb['ListenerDescriptions']:
                                        if not listener_descriptions['Listener']['Protocol'] in [
                                            'HTTPS', 'SSL']:
                                            output.append(
                                                OrderedDict(
                                                    ResourceId=elb['LoadBalancerName'],
                                                    ResourceName=elb['LoadBalancerName'],
                                                    ResourceType='elb'))
                                else:
                                    output.append(
                                        OrderedDict(
                                            ResourceId=elb['LoadBalancerName'],
                                            ResourceName=elb['LoadBalancerName'],
                                            ResourceType='elb'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_web_tier_elb_security_policy(self, **kwargs):
        output, evaluated_resources = self.common_ssl_tls_server_certificate_to_tier(
            'security_policy')
        return output, evaluated_resources

    def aws_web_tier_elbs_health_check(self, **kwargs):
        output, evaluated_resources = self.common_ssl_tls_server_certificate_to_tier(
            'health_check')
        return output, evaluated_resources

    def aws_expired_ssl_tls_certificate(self, **kwargs):
        output = list()
        evaluated_resources = 0
        expiry_days = 0
        now = datetime.now()
        try:
            credentials = self.execution_args['auth_values']
            certificate_list = run_aws_operation(
                credentials, 'iam', 'list_server_certificates')
            if certificate_list['ServerCertificateMetadataList']:
                server_certificate_details = certificate_list['ServerCertificateMetadataList']
                for certificate_details in server_certificate_details:
                    evaluated_resources += 1
                    ssl_expiration_date = certificate_details['Expiration'].replace(tzinfo=None)
                    if (ssl_expiration_date - now).days <= expiry_days:
                        output.append(
                            OrderedDict(
                                ResourceId=str(ssl_expiration_date),
                                ResourceName=str(ssl_expiration_date),
                                ResourceType='IAM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_rds_auto_minor_version_upgrade(self, **kwargs):
        output, evaluated_resources = self.common_rds_describe_db_instances_fun(
            'version_upgrade')
        return output, evaluated_resources

    def aws_rds_desired_instance_type(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            desired_instance_list = list(
                map(str.strip, self.execution_args['args']['desired_instance_list'].split(',')))
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_clusters = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for _data in db_clusters:
                    evaluated_resources += 1
                    if _data['DBInstanceClass'] not in desired_instance_list:
                        output.append(
                            OrderedDict(
                                DBName=_data['DBInstanceIdentifier'],
                                DBType=_data['DBInstanceClass'],
                                ResourceType='rds'
                            ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_cross_account_access(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(credentials, 's3', 'list_buckets')
            operation_args = {}
            owners_id = run_aws_operation(
                credentials, 'sts', 'get_caller_identity').get('Account')
            for bucket in s3_buckets['Buckets']:
                operation_args.update(Bucket=bucket['Name'])
                evaluated_resources += 1
                try:
                    bucket_policy = run_aws_operation(
                        credentials, 's3', 'get_bucket_policy', operation_args)
                    policy = bucket_policy['Policy']
                    policy = json.loads(policy)
                    for statement in policy['Statement']:
                        aws_account_id = statement['Principal']['AWS'].split(
                            ':')[-2]
                        if aws_account_id != owners_id:
                            output.append(
                                OrderedDict(
                                    ResourceId=bucket['Name'],
                                    ResourceName=bucket['Name'],
                                    ResourceType="s3"))

                except Exception as e:
                    if 'NoSuchBucketPolicy' in str(e):
                        continue
            if output:
                policy_output = {v['ResourceId']: v for v in output}.values()
                output = policy_output
                return output, evaluated_resources
            else:
                return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_canary_access_token(self, **kwargs):
        output, evaluated_resources = self.iam_root_access(
            'canary_token')
        return output, evaluated_resources

    def aws_iam_root_account_active_signing_certificates(self, **kwargs):
        output, evaluated_resources = self.iam_root_access(
            'root_account_signing_certificates')
        return output, evaluated_resources

    def aws_alb_waf_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    alb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancers')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for alb in alb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerArn=alb['LoadBalancerArn'])
                    alb_info = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancer_attributes',
                        operation_args=operation_args,
                        region_name=region)
                    for logging_info in alb_info['Attributes']:
                        if (logging_info['Key'] ==
                                'waf.fail_open.enabled' and logging_info['Value'] == 'false'):
                            output.append(
                                OrderedDict(
                                    ResourceId=alb['LoadBalancerName'],
                                    ResourceName=alb['LoadBalancerName'],
                                    Resource="elb"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def common_elasticsearch_encryption(self, check_type):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args.get('auth_values', {})
            regions = [region.get('id') for region in self.execution_args.get('regions', {})]
            for region in regions:
                try:
                    response_domain_names = run_aws_operation(credentials, 'es', 'list_domain_names',
                                                              region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domain_name in response_domain_names['DomainNames']:
                    evaluated_resources += 1
                    operation_args.update(DomainName=domain_name.get('DomainName', {}))
                    elasticsearch_domain_names = run_aws_operation(credentials, 'es', 'describe_elasticsearch_domain',
                                                                   operation_args, region_name=region,
                                                                   response_key='DomainStatus')
                    if check_type == 'Enabled':
                        if elasticsearch_domain_names.get('DomainStatus', {}).get('NodeToNodeEncryptionOptions',
                                                                                  {}).get(
                            'Enabled'):
                            output.append(OrderedDict(ResourceId=domain_name.get('DomainName', {}),
                                                      ResourceName=domain_name.get('DomainName', {}),
                                                      Resource='ElasticSearch'))
                    elif check_type == 'Disable':
                        if not elasticsearch_domain_names.get('DomainStatus', {}).get('NodeToNodeEncryptionOptions',
                                                                                      {}).get('Enabled'):
                            output.append(OrderedDict(ResourceId=domain_name.get('DomainName', {}),
                                                      ResourceName=domain_name.get('DomainName', {}),
                                                      Resource='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_elasticsearch_encryption_in_transit(self):
        output, evaluated_resources = self.common_elasticsearch_encryption('Disable')
        return output, evaluated_resources

    def ensure_aws_elasticsearch_Service_domains_are_not_exposed_to_everyone(
            self,
            **kwargs):
        output = list()
        operation_args = {}
        es_list = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'list_domain_names',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response['DomainNames']:
                    es_list.append(domains['DomainName'])
                    operation_args.update(DomainName=domains['DomainName'])
                    esresponse = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args,
                        region_name=region)

                    value = esresponse['DomainStatus']['AccessPolicies']
                    policies = json.loads(value)
                    for policy in policies['Statement']:
                        if policy['Principal']['AWS'] == "*":
                            output.append(
                                OrderedDict(
                                    ResourceId=domains['DomainName'],
                                    ResourceName=domains['DomainName'],
                                    Resource='es',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))

            return output, es_list
        except Exception as e:
            raise Exception(e.message)

    def aws_audit_elasticsearch_nodetonode_encryption(self):
        output, evaluated_resources = self.common_elasticsearch_encryption('Enabled')
        return output, evaluated_resources

    def aws_iam_policy_in_use(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            user_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            operation_args = {}
            for user in user_response:
                evaluated_resources += 1
                operation_args.update(UserName=user['UserName'])
                user_policy = run_aws_operation(
                    credentials, 'iam', 'list_user_policies', operation_args)
                if not user_policy['PolicyNames']:
                    output.append(
                        OrderedDict(
                            ResourceId=user['UserName'],
                            ResourceName=user['UserName'],
                            ResourceType='iam'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_audit_s3_bucket_open_to_the_world_that_web_server(
            self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(
                credentials, 's3', 'list_buckets')
            operation_args = {}
            for bucket in s3_buckets['Buckets']:
                operation_args.update(Bucket=bucket['Name'])
                evaluated_resources += 1
                try:
                    bucket_response = run_aws_operation(
                        credentials, 's3', 'get_bucket_policy_status', operation_args)
                    if bucket_response:
                        output.append(
                            OrderedDict(
                                ResourceId=bucket['Name'],
                                ResourceName=bucket['Name'],
                                ResourceType='s3'))
                except Exception as err:
                    if 'NoSuchBucketPolicy' in str(err):
                        continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_policy_grantee_check(self):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            account_access_list = list(map(str.strip, self.execution_args["args"]['account_access_list'].split(',')))
            s3_buckets = run_aws_operation(
                credentials,
                's3',
                'list_buckets')
            operation_args = {}
            for bucket in s3_buckets['Buckets']:
                operation_args.update(Bucket=bucket['Name'])
                evaluated_resources += 1
                try:
                    bucket_policy = run_aws_operation(
                        credentials, 's3', 'get_bucket_policy', operation_args)
                    policy = bucket_policy['Policy']
                    policy = json.loads(policy)
                    for statement in policy['Statement']:
                        aws_account_id = statement['Principal']['AWS'].split(
                            ':')[-2]
                        if aws_account_id != account_access_list:
                            output.append(
                                OrderedDict(
                                    ResourceId=bucket['Name'],
                                    ResourceName=bucket['Name'],
                                    ResourceType="s3"))
                except Exception as e:
                    if 'NoSuchBucketPolicy' in str(e):
                        continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_multi_availability_zone_not_enabled_instance(self):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_clusters = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_clusters',
                        region_name=region,
                        response_key='DBClusters')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for data in db_clusters:
                    evaluated_resources += 1
                    if not data['MultiAZ']:
                        output.append(
                            OrderedDict(
                                ResourceId=data['DBClusterIdentifier'],
                                ResourceName=data['DBClusterIdentifier'],
                                Resource='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cloudtrail_s3_dataevents_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args.get('regions', {})]
            for region in regions:
                evaluated_resources += 1
                try:
                    trail_response = run_aws_operation(
                        credentials,
                        'cloudtrail',
                        'describe_trails',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for trail in trail_response['trailList']:
                    operation_args.update(TrailName=trail['Name'])
                    try:
                        event_response = run_aws_operation(
                            credentials,
                            'cloudtrail',
                            'get_event_selectors',
                            operation_args=operation_args,
                            region_name=region)
                        for event in event_response['EventSelectors']:
                            print(event)
                    except Exception as e:
                        if 'EventSelectors' in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=trail['Name'],
                                    ResourceName=trail['Name'],
                                    ResourceType='cloudtrail'))
                        elif 'TrailNotFoundException' in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=trail['Name'],
                                    ResourceName=trail['Name'],
                                    ResourceType='cloudtrail'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_eip_attached(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    address = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_addresses',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ip in address['Addresses']:
                    evaluated_resources += 1
                    if not 'InstanceId' in ip:
                        output.append(
                            OrderedDict(
                                ResourceId=ip['PublicIp'],
                                ResourceName=ip['PublicIp'],
                                ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_check_attached_policies(self, function, credentials, id, name, operation_args, policy_arns):
        try:
            output = list()
            credentials = self.execution_args['auth_values']
            attached_group_policies = run_aws_operation(
                credentials,
                'iam',
                function,
                operation_args,
                response_key='AttachedPolicies')
            for policy in attached_group_policies:
                if policy['PolicyArn'] in policy_arns:
                    output.append(
                        OrderedDict(
                            ResourceId=id,
                            ResourceName=name,
                            Resource='iam'))
            return output
        except Exception as e:
            raise Exception(e.message)

    def aws_audit_iam_policy_blacklisted_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            policy_arns = list(map(str.strip, self.execution_args['args']['policy_arns'].split(',')))
            operation_args = {}
            # Group Resource
            group_response = run_aws_operation(
                credentials, 'iam', 'list_groups', response_key='Groups')
            for group in group_response:
                evaluated_resources += 1
                operation_args.update(GroupName=group['GroupName'])
                response = self.aws_iam_check_attached_policies('list_attached_group_policies', credentials,
                                                                group['GroupId'],
                                                                group['GroupName'], operation_args, policy_arns)
                if response:
                    output.append(response)
            # User Resource
            user_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for user in user_response:
                evaluated_resources += 1
                operation_args = {}
                operation_args.update(UserName=user['UserName'])
                response = self.aws_iam_check_attached_policies('list_attached_user_policies', credentials,
                                                                user['UserId'], user['UserName'],
                                                                operation_args, policy_arns)
                if response:
                    output.append(response)
            # Role Resource
            role_response = run_aws_operation(
                credentials, 'iam', 'list_roles', response_key='Roles')
            for role in role_response:
                evaluated_resources += 1
                operation_args = {}
                operation_args.update(RoleName=role['RoleName'])
                response = self.aws_iam_check_attached_policies('list_attached_role_policies', credentials,
                                                                role['RoleId'], role['RoleName'],
                                                                operation_args, policy_arns)
                if response:
                    output.append(response)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_unrestricted_port_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            port_number = self.execution_args['args']['port_number']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region,
                        response_key='SecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups:
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ippermissions in security_group['IpPermissions']:
                        if (security_group_ippermissions['IpProtocol']) != '-1':
                            if (security_group_ippermissions['FromPort'] == port_number
                                    and security_group_ippermissions['ToPort'] == port_number):
                                for ip_address in security_group_ippermissions['IpRanges']:
                                    if ip_address['CidrIp'] == '0.0.0.0/0':
                                        security_group_compliant = False
                                for ip_address in security_group_ippermissions['Ipv6Ranges']:
                                    if ip_address['CidrIpv6'] == '::/0':
                                        security_group_compliant = False

                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group['GroupId'],
                                ResourceName=security_group['GroupId'],
                                Resource="security_group"))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_aurora_mysql_backtracing_enabled(self, **kwargs):
        output = list()
        evaluated_resources = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_cluster_info = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_clusters',
                        region_name=region,
                        response_key='DBClusters')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for db_info in rds_cluster_info:
                    evaluated_resources.append(
                        db_info.get('DBClusterIdentifier'))
                    if db_info['Engine'] == 'aurora-mysql':
                        try:
                            print(db_info['BacktrackWindow'])
                        except KeyError as e:
                            output.append(
                                OrderedDict(
                                    ResourceId=db_info['DBClusterIdentifier'],
                                    ResourceName=db_info['DBClusterIdentifier'],
                                    Resource='aurora',
                                    Region=region,
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name']))

            return output, len(evaluated_resources)
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_enable_rds_transport_encryption(self, **kwargs):
        output = list()
        rds_cluster_name = list()
        operation_args = {}
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                print(region)
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for db_instance in rds_response:
                    rds_cluster_name.append(
                        db_instance['DBInstanceIdentifier'])
                    for db_parameter in db_instance['DBParameterGroups']:
                        operation_args.update(
                            DBParameterGroupName=db_parameter['DBParameterGroupName'])
                        dbparameter_response = run_aws_operation(
                            credentials,
                            'rds',
                            'describe_db_parameters',
                            region_name=region,
                            operation_args=operation_args)
                        for parameter in dbparameter_response['Parameters']:
                            if parameter['ParameterName'] == 'rds.force_ssl':
                                if parameter['ParameterValue'] == "0":
                                    output.append(
                                        OrderedDict(
                                            ResourceId=db_instance['DBInstanceIdentifier'],
                                            ResourceName=db_instance['DBInstanceIdentifier'],
                                            Resource='RDS',
                                            ServiceAccountId=service_account_id,
                                            ServiceAccountName=self.execution_args['service_account_name']))

            return output, len(rds_cluster_name)
        except Exception as e:
            raise Exception(e.message)

    def aws_rds_enable_serverless_log_exports(self, **kwargs):
        try:
            output, evaluated_resources = self.check_rds_config(
                'EnabledCloudwatchLogsExports')
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_reserved_db_instance_expiration(self):
        try:
            output = list()
            evaluated_resources = 0
            now = datetime.now()
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            expiry_days = self.execution_args['args'].get('expiry_days', 30)
            for region in regions:
                try:
                    db_clusters = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_reserved_db_instances',
                        region_name=region,
                        response_key='ReservedDBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for each_rd_instance in db_clusters:
                    evaluated_resources += 1
                    ri_start_time = each_rd_instance["StartTime"].replace(
                        tzinfo=None)
                    expire_time = ri_start_time + timedelta(seconds=each_rd_instance['Duration'])
                    if (expire_time - now).days <= expiry_days:
                        output.append(
                            OrderedDict(
                                DBName=each_rd_instance['DBInstanceIdentifier'],
                                DBType=each_rd_instance['DBInstanceClass'],
                                ResourceType='DBInstances'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_redshift_require_tls_ssl(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    clusters_response = run_aws_operation(
                        credentials,
                        'redshift',
                        'describe_clusters',
                        region_name=region,
                        response_key='Clusters')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster in clusters_response:
                    evaluated_resources += 1
                    for cluster_parameter_group in cluster['ClusterParameterGroups']:
                        operation_args.update(
                            ParameterGroupName=cluster_parameter_group['ParameterGroupName'])
                        cluster_parameters = run_aws_operation(
                            credentials,
                            'redshift',
                            'describe_cluster_parameters',
                            region_name=region,
                            operation_args=operation_args,
                            response_key='Parameters')
                        for cluster_parameter in cluster_parameters:
                            if cluster_parameter['ParameterName'] == 'require_ssl' and cluster_parameter[
                                'ParameterValue'] == 'false':
                                output.append(
                                    OrderedDict(
                                        ResourceId=cluster['ClusterIdentifier'],
                                        ResourceName=cluster['ClusterIdentifier'],
                                        ResourceType="RedShift"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_ami_naming_convention(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            pattern = re.compile(self.execution_args.get("ami_naming_pattern"))
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Owners=['self', ])
                    ec2_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_images',
                        region_name=region,
                        operation_args=operation_args)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for images in ec2_response['Images']:
                    evaluated_resources += 1
                    if images['Tags']:
                        for tag in images['Tags']:
                            if tag['Key'] == 'Name':
                                if not bool(re.search(pattern, tag['Value'])):
                                    output.append(
                                        OrderedDict(
                                            ResourceId=images['ImageId'],
                                            ResourceName=images['ImageId'],
                                            ResourceType='ec2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_elb_cross_zone_load_balancing_enabled(self, **kwargs):
        try:
            output = list()
            elb_list = list()
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    elb_list.append(elb['LoadBalancerName'])
                    operation_args.update(
                        LoadBalancerName=elb['LoadBalancerName'])
                    elb_info = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancer_attributes',
                        region_name=region,
                        operation_args=operation_args)
                    if elb_info.get(
                            'LoadBalancerAttributes',
                            {}).get(
                        'CrossZoneLoadBalancing',
                        {}).get('Enabled') == False:
                        output.append(
                            OrderedDict(
                                ResourceId=elb['LoadBalancerName'],
                                ResourceName=elb['LoadBalancerName'],
                                ResourceType='elb'))
            return output, len(elb_list)
        except Exception as e:
            raise Exception(str(e))

    def aws_cloudtrail_enable_object_lock_for_s3_buckets(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            cloudtrail_reponse = run_aws_operation(
                credentials, 'cloudtrail', 'describe_trails')
            for trail in cloudtrail_reponse['trailList']:
                evaluated_resources += 1
                operation_args.update(Bucket=trail['S3BucketName'])
                try:
                    s3_bucket_MFA_delete_enabled = run_aws_operation(
                        credentials, 's3', 'get_object_lock_configuration', operation_args=operation_args)
                    if s3_bucket_MFA_delete_enabled['MFADelete'] != 'Enabled':
                        output.append(
                            OrderedDict(
                                ResourceId=trail['Name'],
                                ResourceName=trail['Name'],
                                ResourceType='S3'))
                except Exception as e:
                    if 'ObjectLockConfigurationNotFoundError' in str(e):
                        output.append(
                            OrderedDict(
                                ResourceId=trail['Name'],
                                ResourceName=trail['Name'],
                                ResourceType='Cloudtrail'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_aws_elasticsearch_domains_are_encrypted_with_kms_customer_master_keys(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response.get('DomainNames'):
                    operation_args = dict(DomainName=domains.get('DomainName'))
                    ec_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args, region_name=region)
                    kms_key_id = ec_response.get('DomainStatus', {}).get('EncryptionAtRestOptions', {}).get('KmsKeyId')
                    operation_args_kms = dict(KeyId=kms_key_id)
                    kms_list_aliases = run_aws_operation(
                        credentials,
                        'kms',
                        'list_aliases',
                        operation_args_kms, region_name=region)
                    for kms_list_alias in kms_list_aliases.get('Aliases'):
                        if kms_list_alias.get('AliasName') == 'alias/aws/es':
                            output.append(OrderedDict(
                                ResourceId=domains['DomainName'],
                                ResourceName=domains['DomainName'],
                                ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_only_whitelisted_ip_addresses_can_access_your_amazon_elasticsearch_domains(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            approved_ipv4 = self.execution_args['args'].get('approved_ipv4')
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response.get('DomainNames'):
                    evaluated_resources += 1
                    operation_args = dict(DomainName=domains.get('DomainName'))
                    des_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args, region_name=region)
                    value = des_response.get('DomainStatus', {}).get('AccessPolicies')
                    policies = json.loads(value)
                    for policy in policies.get('Statement'):
                        if policy.get('Condition', {}).get('IpAddress', {}).get(
                                'aws:SourceIp') not in approved_ipv4.split(','):
                            output.append(OrderedDict(
                                ResourceId=domains['DomainName'],
                                ResourceName=domains['DomainName'],
                                ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_aws_elasticsearch_clusters_do_not_allow_unknown_cross_account_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            allowed_arn = self.execution_args['args'].get('allowed_arn')
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response['DomainNames']:
                    evaluated_resources += 1
                    operation_args = dict(DomainName=domains.get('DomainName'))
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args, region_name=region)
                    value = es_response.get('DomainStatus', {}).get('AccessPolicies')
                    policies = json.loads(value)
                    for policy in policies.get('Statement'):
                        if policy.get('Principal', {}).get('AWS') != allowed_arn:
                            output.append(OrderedDict(
                                ResourceId=domains.get('DomainName'),
                                ResourceName=domains.get('DomainName'),
                                ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_aws_elasticsearch_clusters_are_using_dedicated_master_nodes(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response.get('DomainNames'):
                    evaluated_resources += 1
                    operation_args = dict(DomainName=domains.get('DomainName'))
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args, region_name=region)
                    if not es_response.get('DomainStatus', {}).get('ElasticsearchClusterConfig', {}).get(
                            'DedicatedMasterEnabled'):
                        output.append(OrderedDict(
                            ResourceId=domains['DomainName'],
                            ResourceName=domains['DomainName'],
                            ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_that_all_your_aws_elasticsearch_cluster_instances_are_of_given_instance_types(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            instance_type = self.execution_args['args'].get('instance_type')
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response.get('DomainNames'):
                    evaluated_resources += 1
                    operation_args = dict(DomainName=domains.get('DomainName'))
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args, region_name=region)
                    if es_response.get('DomainStatus', {}).get('ElasticsearchClusterConfig', {}).get(
                            'InstanceType') not in instance_type.split(','):
                        output.append(OrderedDict(
                            ResourceId=domains.get('DomainName'),
                            ResourceName=domains.get('DomainName'),
                            ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_aws_elasticsearch_service_domains_are_not_exposed_to_everyone(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response.get('DomainNames'):
                    evaluated_resources += 1
                    operation_args = dict(DomainName=domains.get('DomainName'))
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args, region_name=region)
                    value = es_response.get('DomainStatus', {}).get('AccessPolicies')
                    policies = json.loads(value)
                    for policy in policies.get('Statement'):
                        if policy.get('Principal', {}).get('AWS') == "*":
                            output.append(OrderedDict(
                                ResourceId=domains['DomainName'],
                                ResourceName=domains['DomainName'],
                                ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_aws_elasticsearch_domains_are_accessible_from_a_vpc(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response.get('DomainNames'):
                    evaluated_resources += 1
                    operation_args = dict(DomainName=domains.get('DomainName'))
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args, region_name=region)
                    if not es_response.get('DomainStatus', {}).get('Endpoint'):
                        output.append(OrderedDict(
                            ResourceId=domains['DomainName'],
                            ResourceName=domains['DomainName'],
                            ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def ensure_high_availability_for_your_aws_elasticsearch_clusters_by_enabling_the_zone_awareness_feature(
            self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials, 'es', 'list_domain_names', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response.get('DomainNames'):
                    evaluated_resources += 1
                    operation_args = dict(DomainName=domains.get('DomainName'))
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'describe_elasticsearch_domain',
                        operation_args, region_name=region)
                    if not es_response.get('DomainStatus', {}).get('ElasticsearchClusterConfig', {}).get(
                            'ZoneAwarenessEnabled'):
                        output.append(OrderedDict(
                            ResourceId=domains['DomainName'],
                            ResourceName=domains['DomainName'],
                            ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_iam_unnecessary_ssh_public_keys(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args.get('auth_values', {})
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            operation_args = {}
            for iam in iam_response:
                evaluated_resources += 1
                operation_args.update(UserName=iam.get('UserName', {}))
                iam_ssh_response = run_aws_operation(
                    credentials,
                    'iam',
                    'list_ssh_public_keys',
                    operation_args,
                    response_key='SSHPublicKeys')
                if len(iam_ssh_response) > 0:
                    for ssh_key_details in iam_ssh_response:
                        if ssh_key_details['Status'] == 'Active':
                            output.append(
                                OrderedDict(
                                    ResourceId=ssh_key_details.get('SSHPublicKeyId', {}),
                                    ResourceName=ssh_key_details.get('SSHPublicKeyId', {}),
                                    ResourceType='IAM'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_whether_aws_eks_security_groups_are_configured_to_allow_incoming_traffic_only_on_tcp_port_443(
            self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    eks_response = run_aws_operation(
                        credentials, 'eks', 'list_clusters', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster in eks_response.get('clusters'):
                    evaluated_resources += 1
                    operation_args = dict(name=cluster)
                    eks = run_aws_operation(
                        credentials,
                        'eks',
                        'describe_cluster',
                        operation_args, region_name=region)
                    operation_args_sg = dict(
                        GroupIds=[eks.get('cluster', {}).get('resourcesVpcConfig', {}).get('clusterSecurityGroupId')])
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        operation_args_sg, region_name=region)
                    for security_group in security_groups.get('SecurityGroups'):
                        for security_group_ip_permissions in security_group.get('IpPermissions'):
                            if security_group_ip_permissions.get('IpProtocol') != '-1':
                                if security_group_ip_permissions.get(
                                        'FromPort') != 443 and security_group_ip_permissions.get('ToPort') != 443:
                                    output.append(OrderedDict(
                                        ResourceId=cluster,
                                        ResourceName=cluster,
                                        ResourceType='EKS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def verify_that_your_lightsail_buckets_are_not_publicly_accessible(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    light_response = run_aws_operation(
                        credentials,
                        'lightsail',
                        'get_buckets',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for bucket in light_response.get('buckets'):
                    evaluated_resources += 1
                    if bucket.get('accessRules', {}).get('getObject') == 'public' and bucket.get('accessRules', {}).get(
                            'allowPublicOverrides'):
                        output.append(OrderedDict(
                            ResourceId=bucket.get('name'),
                            ResourceName=bucket.get('name'),
                            ResourceType='LightSail'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_whether_instances_are_attached_to_lightsail_buckets(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args = dict(includeConnectedResources=True)
                    light_response = run_aws_operation(
                        credentials,
                        'lightsail',
                        'get_buckets',
                        operation_args,
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for resources in light_response.get('buckets'):
                    evaluated_resources += 1
                    if not resources.get('resourcesReceivingAccess'):
                        output.append(OrderedDict(
                            ResourceId=resources.get('name'),
                            ResourceName=resources.get('name'),
                            ResourceType='LightSail'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def get_address_prefix_for_subnet(self, address_prefix):
        try:
            available_address_prefixes = list(ip_network(address=address_prefix, strict=False))
            return list(map(str, available_address_prefixes))
        except Exception as e:
            return list()

    def form_vpc_level_access(self, df, network_dict, copy_df):
        try:
            network_distint_name = df.get("network_name", "") + df.get("cloud_provider_unique_id") + "_" + df.get(
                "list_of_entities_by_type")
            if network_distint_name in network_dict.keys():
                return network_dict[network_distint_name]
            final_result = False
            filtered_df = copy_df.loc[(copy_df["network_name"] == df.get("list_of_entities_by_type"))]
            if filtered_df.empty:
                return False
            filtered_df = filtered_df.head(1)
            is_firewall_configured_for_vpc = False
            allowed_ips_for_firewall = df.get("network_configurations.firewalls.fire_wall_address_prefixes", [])
            allowed_ips_for_network = filtered_df["network_configurations.available_ips"].item()
            for ip in allowed_ips_for_firewall:
                if '/' in ip:
                    ip = self.get_address_prefix_for_subnet(ip)
                    ip = ip[0]
                list_of_netowkrs = netaddr.all_matching_cidrs(ip, allowed_ips_for_network)
                if list_of_netowkrs:
                    is_firewall_configured_for_vpc = True
                    break
            rule_type = df.get("rule_type", "allow")
            if rule_type == "allow":
                final_result = True if not is_firewall_configured_for_vpc else False
            if rule_type == "deny":
                final_result = True if is_firewall_configured_for_vpc else False
            network_dict.update({network_distint_name: final_result})
            return final_result
        except Exception as e:
            return False

    def form_region_level_access(self, df, network_dict, copy_df):
        try:
            if df.get("is_violated"):
                return True
            filtered_df = copy_df.loc[(copy_df["subnet_region"] == df.get("list_of_entities_by_type"))]
            name_to_check = df.get("subnet_region", "") + df.get("list_of_entities_by_type")
            if name_to_check in network_dict.keys():
                return network_dict[name_to_check]
            final_result = False
            filtered_df = filtered_df.head(1)
            is_firewall_configured_for_region = False
            allowed_ips_for_firewall = list()
            allowed_ips_for_network = list()
            for index, each_df in filtered_df.iterrows():
                allowed_ips_for_firewall.extend(
                    each_df.get("network_configurations.firewalls.fire_wall_address_prefixes", []))
                allowed_ips_for_network.extend(each_df["network_configurations.available_ips"])
            allowed_ips_for_firewall = df.get("network_configurations.firewalls.fire_wall_address_prefixes", [])
            allowed_ips_for_network = filtered_df["network_configurations.available_ips"].item()
            for ip in allowed_ips_for_firewall:
                if '/' in ip:
                    ip = self.get_address_prefix_for_subnet(ip)
                    ip = ip[0]
                list_of_netowkrs = netaddr.all_matching_cidrs(ip, allowed_ips_for_network)
                if list_of_netowkrs:
                    is_firewall_configured_for_region = True
                    break
            rule_type = df.get("rule_type", "allow")
            if rule_type == "allow":
                final_result = True if not is_firewall_configured_for_region else False
            if rule_type == "deny":
                final_result = True if is_firewall_configured_for_region else False
            network_dict.update({name_to_check: final_result})
            return final_result
        except Exception as e:
            return False

    def form_folder_level_access(self, df, network_dict, copy_df):
        try:
            if df.get("is_violated"):
                return True
            name_to_check = df.get("folder_name", "") + df.get("list_of_entities_by_type")
            if name_to_check in network_dict.keys():
                return network_dict[name_to_check]
            final_result = False
            filtered_df_for_source_df = copy_df.loc[
                (copy_df["organization_structure"].str.contains(df.get("folder_name")))]
            if filtered_df_for_source_df.empty:
                return False
            filtered_df_for_destination = copy_df.loc[(copy_df["organization_structure"].str
                                                       .contains(df.get("list_of_entities_by_type")))]
            if filtered_df_for_destination.empty:
                return False
            list_of_ips_to_check_with_filtered_df_source = set(
                itertools.chain.from_iterable(filtered_df_for_source_df["network_configurations.available_ips"]))
            list_of_ips_to_check_with_filtered_df_destination = set(
                itertools.chain.from_iterable(filtered_df_for_destination["network_configurations.available_ips"]))
            allowed_ips_for_firewall_for_source = set(itertools.chain.from_iterable(
                filtered_df_for_source_df["network_configurations.firewalls.fire_wall_address_prefixes"]))
            allowed_ips_for_firewall_for_destination = set(itertools.chain.from_iterable(
                filtered_df_for_destination["network_configurations.firewalls.fire_wall_address_prefixes"]))
            is_firewall_configured_for_folder = False

            for ip in list(allowed_ips_for_firewall_for_source):
                if ip == '0.0.0.0/0':
                    is_firewall_configured_for_folder = True
                    break
                if '/' in ip:
                    ip = self.get_address_prefix_for_subnet(ip)
                    ip = ip[0]
                list_of_netowkrs = netaddr.all_matching_cidrs(ip, list(allowed_ips_for_firewall_for_destination))
                if list_of_netowkrs:
                    is_firewall_configured_for_folder = True
                    break
            rule_type = df.get("rule_type", "allow")
            if rule_type == "allow":
                final_result = True if is_firewall_configured_for_folder else False
            if rule_type == "deny":
                final_result = False if not is_firewall_configured_for_folder else True
            network_dict.update({name_to_check: final_result})
            return final_result
        except Exception as e:
            return False

    def check_cross_account_access_to_give_other_aws_accounts_access_to_objects_in_your_bucket(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args = dict(includeConnectedResources=True)
                    light_response = run_aws_operation(
                        credentials,
                        'lightsail',
                        'get_buckets',
                        operation_args,
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for resources in light_response['buckets']:
                    evaluated_resources += 1
                    if resources.get('readonlyAccessAccounts'):
                        output.append(OrderedDict(
                            ResourceId=resources.get('name'),
                            ResourceName=resources.get('name'),
                            Resource='LightSail'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_cost_category_definition(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            now = datetime.utcnow()
            start_day = int(self.execution_args.get('args', {}).get("start_day", "1"))
            if 1 <= start_day <= now.day:
                start_date = now.replace(day=start_day).strftime("%Y-%m-%d")
                end_date = now.strftime("%Y-%m-%d")
                try:
                    credentials = self.execution_args['auth_values']
                    if credentials["account_type"] == "master_account":
                        try:
                            organization_hierarchy_values = self.execution_args.get('master_account_metadata', {}). \
                                get('organization_hierarchy', [])
                        except Exception as e:
                            raise Exception('Unable to get organization hierarchy. Error {}'.format(str(e)))
                        evaluated_resources += 1
                        cost_category = run_aws_operation(credentials, 'ce', 'get_cost_categories',
                                                          operation_args={'TimePeriod': {'Start': start_date,
                                                                                         'End': end_date}})
                        if len(cost_category.get('CostCategoryNames', list())) == 0:
                            if organization_hierarchy_values:
                                for org in organization_hierarchy_values:
                                    if org['id'] == self.execution_args['aws_account_id']:
                                        output.append(OrderedDict(ResourceID=self.execution_args['aws_account_id'],
                                                                  ResourceName=org['name'],
                                                                  Resource='Accounts'))
                            else:
                                output.append(OrderedDict(ResourceID=self.execution_args['aws_account_id'],
                                                          ResourceName=self.execution_args['aws_account_id'],
                                                          Resource='Accounts'))
                    return output, evaluated_resources
                except Exception as e:
                    raise Exception(
                        'Permission Denied. Error {}'.format(str(e)))
            else:
                raise Exception("Day is not within the range (1, current day)")
        except Exception as e:
            raise Exception(str(e))

    def org_tree_util(self, param):
        return {a: b for a, b in param.items() if a != 'parent'}

    def merge_two_dicts(self, a, b):
        return {k: v for d in [a, b] for k, v in d.items()}

    def org_form_tree(self, param, _start=None):
        return [self.org_tree_util((self.merge_two_dicts(i, {'children': self.org_form_tree(param, i['id'])})))
                for i in param if i['parent'] == _start]

    def remove_parent_children(self, org_data, match):
        if isinstance(org_data, (dict, list)):
            for k, v in (org_data.items() if isinstance(org_data, dict) else enumerate(org_data)):
                if v == match:
                    org_data['type'] = []
                    org_data['id'] = []
                    org_data['children'] = []
                self.remove_parent_children(v, match)

    def remove_parent_only(self, org_data, match):
        if isinstance(org_data, (dict, list)):
            for k, v in (org_data.items() if isinstance(org_data, dict) else enumerate(org_data)):
                if v == match:
                    org_data['type'] = []
                    org_data['id'] = []
                self.remove_parent_only(v, match)

    def get_ous(self, org_data, ou_list):
        if isinstance(org_data, (dict, list)):
            for key, val in (org_data.items() if isinstance(org_data, dict) else enumerate(org_data)):
                if val == 'ORGANIZATIONAL_UNIT' or val == 'ROOT':
                    ou_list.append({'id': org_data['id'], 'name': org_data['name']})
                self.get_ous(val, ou_list)
        return ou_list

    def aws_audit_region_restriction_using_scp(self, **kwargs):
        output = list()
        ou_list = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                organization_hierarchy_values = self.execution_args.get('master_account_metadata', {}). \
                    get('organization_hierarchy', [])
            except Exception as e:
                raise Exception('Unable to get organization hierarchy. Error {}'.format(str(e)))

            for i in organization_hierarchy_values:
                if i["type"] == "ROOT":
                    i['parent'] = None
            org_tree = self.org_form_tree(organization_hierarchy_values)
            ou_list = self.get_ous(org_tree, ou_list)

            for ou_id in ou_list:
                evaluated_resources += 1
                policies_for_target = run_aws_operation(credentials, 'organizations',
                                                        'list_policies_for_target',
                                                        operation_args={
                                                            "TargetId": ou_id['id'],
                                                            "Filter": "SERVICE_CONTROL_POLICY"},
                                                        response_key='Policies')
                for policy in policies_for_target:
                    policy_description = run_aws_operation(credentials, 'organizations',
                                                           'describe_policy',
                                                           operation_args={"PolicyId": policy['Id']})
                    policy_content = json.loads(policy_description.get('Policy', {}).get('Content'))
                    if policy_content.get('Statement') and 'Condition' in policy_content['Statement'][0]:
                        condition_dict = policy_content['Statement'][0]['Condition']
                        for item in condition_dict.values():
                            if item.get('aws:RequestedRegion'):
                                self.remove_parent_children(org_tree, ou_id['id'])

            ou_list = []
            ou_list = self.get_ous(org_tree, ou_list)
            for ou_id in ou_list:
                if ou_id['name'] == "Root":
                    continue
                output.append(OrderedDict(ResourceID=ou_id['id'],
                                          ResourceName=ou_id['name'],
                                          Resource='Organization_unit'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_resource_restriction_using_scp(self, **kwargs):
        output = list()
        ou_list = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                organization_hierarchy_values = self.execution_args.get('master_account_metadata', {}). \
                    get('organization_hierarchy', [])
            except Exception as e:
                raise Exception('Unable to get organization hierarchy. Error {}'.format(str(e)))

            for i in organization_hierarchy_values:
                if i["type"] == "ROOT":
                    i['parent'] = None
            org_tree = self.org_form_tree(organization_hierarchy_values)
            ou_list = self.get_ous(org_tree, ou_list)
            for ou_id in ou_list:
                evaluated_resources += 1
                policies_for_target = run_aws_operation(credentials, 'organizations',
                                                        'list_policies_for_target',
                                                        operation_args={
                                                            "TargetId": ou_id['id'],
                                                            "Filter": "SERVICE_CONTROL_POLICY"},
                                                        response_key='Policies'
                                                        )
                for policy in policies_for_target:
                    policy_description = run_aws_operation(credentials, 'organizations',
                                                           'describe_policy',
                                                           operation_args={"PolicyId": policy['Id']}
                                                           )
                    policy_content = json.loads(policy_description.get('Policy', {}).get('Content'))
                    if '*' not in policy_content['Statement'][0]['Resource']:
                        if policy_content['Statement'][0]['Effect'] == "Deny":
                            self.remove_parent_children(org_tree, ou_id['id'])
                        else:
                            self.remove_parent_only(org_tree, ou_id['id'])
            ou_list = []
            ou_list = self.get_ous(org_tree, ou_list)
            for ou_id in ou_list:
                if ou_id['name'] == "Root":
                    continue
                output.append(OrderedDict(ResourceID=ou_id['id'],
                                          ResourceName=ou_id['name'],
                                          Resource='Organization_unit'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_scp_configured_at_ou_level(self, **kwargs):
        output = list()
        ou_list = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                organization_hierarchy_values = self.execution_args.get('master_account_metadata', {}). \
                    get('organization_hierarchy', [])
            except Exception as e:
                raise Exception('Unable to get organization hierarchy. Error {}'.format(str(e)))
            for ou in organization_hierarchy_values:
                if ou['type'] == 'ORGANIZATIONAL_UNIT':
                    ou_list.append((ou['id'], ou['name']))
            for ou_id in ou_list:
                evaluated_resources += 1
                try:
                    policies_for_target = run_aws_operation(credentials, 'organizations',
                                                            'list_policies_for_target',
                                                            operation_args={
                                                                "TargetId": ou_id[0],
                                                                "Filter": "SERVICE_CONTROL_POLICY"},
                                                            response_key='Policies')
                    if len(policies_for_target) == 0:
                        output.append(OrderedDict(ResourceID=ou_id[0],
                                                  ResourceName=ou_id[1],
                                                  Resource='Organization_unit'))
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_budget_notifications(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            budgets = run_aws_operation(credentials, 'budgets', 'describe_budgets',
                                        operation_args={"AccountId": self.execution_args['aws_account_id']})
            if 'Budgets' in budgets:
                for budget in budgets['Budgets']:
                    evaluated_resources += 1
                    notification = run_aws_operation(credentials, 'budgets',
                                                     'describe_notifications_for_budget',
                                                     operation_args={
                                                         "AccountId": self.execution_args['aws_account_id'],
                                                         "BudgetName": budget['BudgetName']},
                                                     response_key='Notifications')
                    if len(notification) == 0:
                        output.append(OrderedDict(ResourceID=budget['BudgetName'],
                                                  ResourceName=budget['BudgetName'],
                                                  Resource='Budget'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_ou_defined(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                if credentials["account_type"] == 'master_account':
                    organization_hierarchy_values = self.execution_args.get('master_account_metadata', {}). \
                        get('organization_hierarchy', [])
                    evaluated_resources += 1
                    for ou in organization_hierarchy_values:
                        if ou['type'] == 'ORGANIZATIONAL_UNIT':
                            break
                    else:
                        master_acc = self.execution_args['master_account_metadata'].get('account_id')
                        if organization_hierarchy_values:
                            for org in organization_hierarchy_values:
                                if master_acc == org['id']:
                                    output.append(OrderedDict(ResourceID=master_acc,
                                                              ResourceName=org['name'],
                                                              Resource='Accounts'))
                        else:
                            output.append(OrderedDict(ResourceID=master_acc,
                                                      ResourceName=master_acc,
                                                      Resource='Accounts'))
            except Exception as e:
                raise Exception('Permission Denied. Error {}'.format(str(e)))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_tag_policy_configured_at_ou_level(self, **kwargs):
        output = list()
        ou_list = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                organization_hierarchy_values = self.execution_args.get('master_account_metadata', {}). \
                    get('organization_hierarchy', [])
            except Exception as e:
                raise Exception('Unable to get organization hierarchy. Error {}'.format(str(e)))

            for i in organization_hierarchy_values:
                if i["type"] == "ROOT":
                    i['parent'] = None
            org_tree = self.org_form_tree(organization_hierarchy_values)
            ou_list = self.get_ous(org_tree, ou_list)
            for ou_id in ou_list:
                tag_policies = run_aws_operation(credentials, 'organizations',
                                                 'list_policies_for_target',
                                                 operation_args={'TargetId': ou_id['id'],
                                                                 'Filter': 'TAG_POLICY'},
                                                 response_key='Policies')
                evaluated_resources += 1
                if len(tag_policies) != 0:
                    self.remove_parent_children(org_tree, ou_id['id'])

            ou_list = []
            self.get_ous(org_tree, ou_list)
            for ou_id in ou_list:
                output.append(OrderedDict(ResourceID=ou_id['id'],
                                          ResourceName=ou_id['name'],
                                          Resource='Organization_unit'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_tag_policy_enabled_at_org_level(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                if credentials["account_type"] == "master_account":
                    org_response = run_aws_operation(credentials, 'organizations',
                                                     'list_roots', response_key='Roots')
                    for root in org_response:
                        evaluated_resources += 1
                        for policy in root['PolicyTypes']:
                            if policy['Type'] == "TAG_POLICY":
                                if policy['Status'] == "ENABLED":
                                    break
                        else:
                            master_acc = self.execution_args['master_account_metadata'].get('account_id')
                            organization_hierarchy_values = self.execution_args.get('master_account_metadata',
                                                                                    {}).get('organization_hierarchy',
                                                                                            [])
                            if organization_hierarchy_values:
                                for org in organization_hierarchy_values:
                                    if master_acc == org['id']:
                                        output.append(OrderedDict(ResourceID=master_acc,
                                                                  ResourceName=org['name'],
                                                                  Resource='Accounts'))

                            else:
                                output.append(OrderedDict(ResourceID=master_acc,
                                                          ResourceName=master_acc,
                                                          Resource='Accounts'))
            except Exception as e:
                raise Exception('Permission Denied. Error {}'.format(str(e)))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_auto_scaling_configured_for_loadbalancers(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            try:
                lb_list = []
                ascg_lb_list = []
                ascg_lbv2_list = []
                lbv2_list = []
                for region in regions:
                    auto_scgroups = run_aws_operation(credentials, 'autoscaling', 'describe_auto_scaling_groups',
                                                      response_key='AutoScalingGroups', region_name=region)
                    for ascg in auto_scgroups:
                        for lbn in ascg['LoadBalancerNames']:
                            ascg_lb_list.append(lbn)
                        for tgarns in ascg['TargetGroupARNs']:
                            target_group = run_aws_operation(credentials, 'elbv2',
                                                             'describe_target_groups',
                                                             operation_args={"TargetGroupArns": [tgarns]},
                                                             response_key='TargetGroups',
                                                             region_name=region)
                            for tg in target_group:
                                ascg_lbv2_list.extend(tg['LoadBalancerArns'])

                    load_balancer = run_aws_operation(credentials, 'elb', 'describe_load_balancers',
                                                      response_key='LoadBalancerDescriptions',
                                                      region_name=region)
                    load_balancer2 = run_aws_operation(credentials, 'elbv2', 'describe_load_balancers',
                                                       response_key='LoadBalancers',
                                                       region_name=region)
                    for lb in load_balancer:
                        evaluated_resources += 1
                        lb_list.append(lb['LoadBalancerName'])
                    for lbv2 in load_balancer2:
                        evaluated_resources += 1
                        lbv2_list.append((lbv2['LoadBalancerArn'], lbv2['LoadBalancerName']))
            except Exception as e:
                raise Exception('Permission Denied or Region is not enabled to access resource.'
                                'Or check load balancer/auto scale configuration. Error {}'.format(str(e)))
            for lb in lb_list:
                if lb not in ascg_lb_list:
                    output.append(OrderedDict(ResourceID=lb,
                                              ResourceName=lb,
                                              Resource='Load_Balancers'))
            for lbv2 in lbv2_list:
                if lbv2[0] not in ascg_lbv2_list:
                    output.append(OrderedDict(ResourceID=lbv2[1],
                                              ResourceName=lbv2[1],
                                              Resource='Load_Balancers'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_cur_configured(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                if credentials["account_type"] == "master_account" and \
                        credentials.get("cloud_type", "aws_standard") != "aws_gov_cloud":
                    try:
                        organization_hierarchy_values = self.execution_args.get('master_account_metadata', {}). \
                            get('organization_hierarchy', [])
                    except Exception as e:
                        raise Exception('Unable to get organization hierarchy. Error {}'.format(str(e)))
                    evaluated_resources += 1
                    time_unit = self.execution_args.get('args', {}).get("TimeUnit", "HOURLY")
                    cur_response = run_aws_operation(credentials, 'cur', 'describe_report_definitions',
                                                     response_key='ReportDefinitions',
                                                     region_name='us-east-1')
                    for unit in cur_response:
                        if unit['TimeUnit'] == time_unit:
                            break
                    else:
                        if organization_hierarchy_values:
                            for org in organization_hierarchy_values:
                                if org['id'] == self.execution_args['aws_account_id']:
                                    output.append(OrderedDict(ResourceID=self.execution_args['aws_account_id'],
                                                              ResourceName=org['name'],
                                                              Resource='Accounts'))
                        else:
                            output.append(OrderedDict(ResourceID=self.execution_args['aws_account_id'],
                                                      ResourceName=self.execution_args['aws_account_id'],
                                                      Resource='Accounts'))
            except Exception as e:
                raise Exception("Permission Denied or Region is not enabled to access resource. Error {} ".
                                format(str(e)))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_linked_account_ou_mapping(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            try:
                if credentials["account_type"] == "master_account":
                    organization_hierarchy_values = self.execution_args.get('master_account_metadata', {}). \
                        get('organization_hierarchy', [])
                    for org in organization_hierarchy_values:
                        if org['type'] == 'ACCOUNT':
                            evaluated_resources += 1
                            if org['parent'].startswith('r-'):
                                output.append(OrderedDict(ResourceID=org['id'],
                                                          ResourceName=org['name'],
                                                          Resource='Accounts'))

            except Exception as e:
                raise Exception("Permission denied. Error {}".format(str(e)))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_vpc_level_network_acccess_validation(self, service_account_id, db_client, evaluated_resources=0):
        try:
            vpc_network_for_gcp_access = dict()
            policy_segregate_query = deepcopy(NetworkConfigurationAccess.rule_segregate_query_for_vpc)
            policy_segregate_query[0].get("$match", {}).update({"applicable_to.id": service_account_id})
            policy_config_details = db_client.network_policy_configurations.aggregate(policy_segregate_query)
            network_config_details = db_client.network_configurations.aggregate(
                [{"$match": {"service_account_id": service_account_id}},
                 {"$unwind": "$network_configurations.firewalls"}])
            network_config_df = pd_json.json_normalize(network_config_details)
            policy_rule_df = pd.DataFrame(policy_config_details)
            if policy_rule_df.empty:
                return policy_rule_df, 0
            if network_config_df.empty:
                return network_config_df, 0
            evaluated_resource_count = network_config_df.shape[0]
            evaluated_resources += evaluated_resource_count
            lst_col = 'list_of_entities_by_type'
            policy_rule_df = pd.DataFrame({
                col: np.repeat(policy_rule_df[col].values, policy_rule_df[lst_col].str.len())
                for col in policy_rule_df.columns.drop(lst_col)}
            ).assign(**{lst_col: np.concatenate(policy_rule_df[lst_col].values)})[policy_rule_df.columns]
            merged_df = pd.merge(network_config_df, policy_rule_df, left_on="network_name",
                                 right_on="name", how='outer')
            merged_df["list_of_entities_by_type"] = merged_df["list_of_entities_by_type"].fillna("NA")
            merged_df["name"] = merged_df["name"].fillna("NA")
            merged_df["scope"] = "VPC"
            copied_network_df = merged_df.copy()
            merged_df['is_violated'] = merged_df.apply(lambda x:
                                                       self.form_vpc_level_access(x, vpc_network_for_gcp_access,
                                                                                  copied_network_df), axis=1)
            merged_df = merged_df[["cloud_provider_unique_id",
                                   "network_configurations.available_ips", "is_violated",
                                   "network_configurations.firewalls.firewall_direction",
                                   "network_configurations.firewalls.firewall_protocol",
                                   "network_configurations.firewalls.firewall_priority",
                                   "network_configurations.firewalls.firewall_ports",
                                   "network_configurations.firewalls.target_service_accounts",
                                   "network_configurations.firewalls.target_tags",
                                   "name", "network_configurations.firewalls.firewall_name",
                                   "list_of_entities_by_type", "rule_type", "scope"]]
            merged_df.drop_duplicates(['name', 'list_of_entities_by_type'], inplace=True)
            merged_df['is_violated'] = merged_df['is_violated'].map({True: 'True', False: 'False'})
            merged_df.dropna(axis=0, subset=["rule_type"], inplace=True)
            merged_df.rename(columns={"list_of_entities_by_type": "Target Entity", "rule_type": "Access_Type",
                                      "network_configurations.firewalls.firewall_direction": "Direction",
                                      "network_configurations.firewalls.firewall_protocol": "Protocol",
                                      "network_configurations.firewalls.firewall_priority": "Priority",
                                      "network_configurations.firewalls.firewall_ports": "Ports",
                                      "network_configurations.firewalls.target_service_accounts": "Target Service Accounts",
                                      "network_configurations.firewalls.target_tags": "Target Tags",
                                      "network_configurations.available_ips": "Available_IP", "scope": "Scope",
                                      "name": "Source Entity", "is_violated": "Is_Compliant",
                                      "cloud_provider_unique_id": "GCP Project ID",
                                      "network_configurations.firewalls.firewall_name": "Firewall Rule Name"},
                             inplace=True)
            merged_df.fillna("NA", inplace=True)
            return merged_df, evaluated_resources
        except Exception as e:
            return pd.DataFrame(), 0

    def check_folder_level_network_access_validation(self, service_account_id, db_client, evaluated_resources=0):
        try:
            folder_level_access = dict()
            policy_segregate_query = deepcopy(NetworkConfigurationAccess.rule_segregate_query_for_folders)
            policy_segregate_query[0].get("$match", {}).update({"applicable_to.id": service_account_id})
            policy_config_details = db_client.network_policy_configurations.aggregate(policy_segregate_query)
            organizational_child_account = db_client.service_account.find(
                {"auth_values.organizational_parent_account": service_account_id}).distinct("_id")
            organizational_child_account = list(map(str, organizational_child_account))
            network_config_details = db_client.network_configurations.aggregate(
                [{"$match": {"service_account_id": {"$in": organizational_child_account}}},
                 {"$unwind": "$network_configurations.firewalls"}])
            network_config_df = pd_json.json_normalize(network_config_details)
            policy_rule_df = pd.DataFrame(policy_config_details)
            if policy_rule_df.empty:
                return policy_rule_df, 0
            if network_config_df.empty:
                return network_config_df, 0
            evaluated_resource_count = network_config_df.shape[0]
            evaluated_resources += evaluated_resource_count
            lst_col = 'list_of_entities_by_type'
            policy_rule_df = pd.DataFrame({
                col: np.repeat(policy_rule_df[col].values, policy_rule_df[lst_col].str.len())
                for col in policy_rule_df.columns.drop(lst_col)}
            ).assign(**{lst_col: np.concatenate(policy_rule_df[lst_col].values)})[policy_rule_df.columns]
            policy_rule_df['join'] = 1
            network_config_df['join'] = 1
            merged_df = network_config_df.merge(
                policy_rule_df, on='join').drop('join', axis=1)
            network_config_df.drop('join', axis=1, inplace=True)
            merged_df['match'] = merged_df.apply(
                lambda x: x.organization_structure.find(x.folder_name), axis=1).ge(0)
            copied_network_df = merged_df.copy()
            merged_df = merged_df.loc[(merged_df["match"] == True)]
            merged_df['is_violated'] = np.where((merged_df['network_configurations.any_source_present'] == True) &
                                                (merged_df['network_configurations.any_destination_present'] == True),
                                                True, False)
            merged_df['is_violated'] = merged_df.apply(lambda x:
                                                       self.form_folder_level_access(x, folder_level_access,
                                                                                     copied_network_df), axis=1)
            merged_df["scope"] = "Folder"
            merged_df = merged_df[["cloud_provider_unique_id",
                                   "network_configurations.available_ips",
                                   "network_configurations.firewalls.firewall_direction",
                                   "network_configurations.firewalls.firewall_protocol",
                                   "network_configurations.firewalls.firewall_priority",
                                   "network_configurations.firewalls.firewall_ports",
                                   "network_configurations.firewalls.target_service_accounts",
                                   "network_configurations.firewalls.target_tags",
                                   "folder_name", "scope", "is_violated",
                                   "list_of_entities_by_type", "rule_type",
                                   "network_configurations.firewalls.firewall_name"]]

            merged_df['is_violated'] = merged_df['is_violated'].map({True: 'True', False: 'False'})
            merged_df.drop_duplicates(['folder_name', 'list_of_entities_by_type'], inplace=True)
            merged_df.dropna(axis=0, subset=["rule_type"], inplace=True)
            merged_df.rename(columns={"list_of_entities_by_type": "Target Entity", "rule_type": "Access_Type",
                                      "network_configurations.available_ips": "Available_IP",
                                      "is_violated": "Is_Compliant",
                                      "network_configurations.firewalls.firewall_direction": "Direction",
                                      "network_configurations.firewalls.firewall_protocol": "Protocol",
                                      "network_configurations.firewalls.firewall_priority": "Priority",
                                      "network_configurations.firewalls.firewall_ports": "Ports",
                                      "network_configurations.firewalls.target_service_accounts": "Target Service Accounts",
                                      "network_configurations.firewalls.target_tags": "Target Tags",
                                      "cloud_provider_unique_id": "GCP Project ID",
                                      "folder_name": "Source Entity", "scope": "Scope",
                                      "network_configurations.firewalls.firewall_name": "Firewall Rule Name"},
                             inplace=True)
            merged_df.fillna("NA", inplace=True)
            return merged_df, evaluated_resources
        except Exception as e:
            return pd.DataFrame(), 0

    def check_region_level_network_access_validation(self, service_account_id, db_client, evaluated_resources=0):
        try:
            region_network_for_gcp_access = dict()
            policy_segregate_query = deepcopy(NetworkConfigurationAccess.rule_segregate_query_for_regions)
            policy_segregate_query[0].get("$match", {}).update({"applicable_to.id": service_account_id})
            policy_config_details = db_client.network_policy_configurations.aggregate(policy_segregate_query)
            network_config_details = db_client.network_configurations.aggregate(
                [{"$match": {"service_account_id": service_account_id}},
                 {"$unwind": "$network_configurations.subnet_list"},

                 {"$addFields": {"subnet_region": {"$arrayElemAt": [
                     {"$split":
                          ["$network_configurations.subnet_list.location", "/"]}, -1]}}}])
            network_config_df = pd_json.json_normalize(network_config_details)
            policy_rule_df = pd.DataFrame(policy_config_details)
            if policy_rule_df.empty:
                return policy_rule_df, 0
            if network_config_df.empty:
                return network_config_df, 0
            evaluated_resource_count = network_config_df.shape[0]
            evaluated_resources += evaluated_resource_count
            lst_col = 'list_of_entities_by_type'
            policy_rule_df = pd.DataFrame({
                col: np.repeat(policy_rule_df[col].values, policy_rule_df[lst_col].str.len())
                for col in policy_rule_df.columns.drop(lst_col)}
            ).assign(**{lst_col: np.concatenate(policy_rule_df[lst_col].values)})[policy_rule_df.columns]
            merged_df = pd.merge(network_config_df, policy_rule_df, left_on="subnet_region",
                                 right_on="region_name", how='outer')
            merged_df["list_of_entities_by_type"] = merged_df["list_of_entities_by_type"].fillna("NA")
            merged_df["name"] = merged_df["name"].fillna("NA")
            merged_df["scope"] = "Region"
            copied_network_df = merged_df.copy()
            merged_df['is_violated'] = merged_df.apply(lambda x:
                                                       self.form_region_level_access(x, region_network_for_gcp_access,
                                                                                     copied_network_df), axis=1)
            merged_df = merged_df[["cloud_provider_unique_id",
                                   "network_configurations.available_ips", "is_violated",
                                   "network_configurations.firewalls.firewall_direction",
                                   "network_configurations.firewalls.firewall_protocol",
                                   "network_configurations.firewalls.firewall_priority",
                                   "network_configurations.firewalls.firewall_ports",
                                   "network_configurations.firewalls.target_service_accounts",
                                   "network_configurations.firewalls.target_tags",
                                   "region_name", "network_configurations.firewalls.firewall_name",
                                   "list_of_entities_by_type", "rule_type", "scope"]]
            merged_df.drop_duplicates(['name', 'list_of_entities_by_type'], inplace=True)
            merged_df['is_violated'] = merged_df['is_violated'].map({True: 'True', False: 'False'})
            merged_df.dropna(axis=0, subset=["rule_type"], inplace=True)
            merged_df.rename(columns={"list_of_entities_by_type": "Target Entity", "rule_type": "Access_Type",
                                      "network_configurations.available_ips": "Available_IP", "scope": "Scope",
                                      "name": "Source Entity", "is_violated": "Is_Compliant",
                                      "cloud_provider_unique_id": "GCP Project Id",
                                      "network_configurations.firewalls.firewall_direction": "Direction",
                                      "network_configurations.firewalls.firewall_protocol": "Protocol",
                                      "network_configurations.firewalls.firewall_priority": "Priority",
                                      "network_configurations.firewalls.firewall_ports": "Ports",
                                      "network_configurations.firewalls.target_service_accounts": "Target Service Accounts",
                                      "network_configurations.firewalls.target_tags": "Target Tags",
                                      "network_configurations.firewalls.firewall_name": "Firewall Rule Name"},
                             inplace=True)
            merged_df.fillna("NA", inplace=True)
            return merged_df, evaluated_resources
        except Exception as e:
            return pd.DataFrame(), 0

    def check_network_access_validation_in_gcp_project(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            final_df = region_level_df = vpc_level_df = folders_level_df = pd.DataFrame()
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            service_account_id = self.execution_args.get("service_account_id")
            query = {"applicable_to.id": str(service_account_id)}
            policy_configuration_result = db.network_policy_configurations.find_one(query)
            if not policy_configuration_result:
                return output, evaluated_resources
            vpc_rule_list = policy_configuration_result.get("schema_details", {}).get("vpc", list())
            region_rule_list = policy_configuration_result.get("schema_details", {}).get("regions", list())
            folders_rule_list = policy_configuration_result.get("schema_details", {}).get("folders", list())
            if vpc_rule_list:
                vpc_level_df, evaluated_resources = self.check_vpc_level_network_acccess_validation(service_account_id,
                                                                                                    db,
                                                                                                    evaluated_resources)
            if folders_rule_list:
                folders_level_df, evaluated_resources = self.check_folder_level_network_access_validation(
                    service_account_id, db,
                    evaluated_resources)
            if region_rule_list:
                region_level_df, evaluated_resources = self.check_region_level_network_access_validation(
                    service_account_id, db,
                    evaluated_resources)
            if not vpc_level_df.empty:
                final_df = pd.concat([final_df, vpc_level_df], ignore_index=True)
            if not folders_level_df.empty:
                final_df = pd.concat([final_df, folders_level_df], ignore_index=True)
            if not region_level_df.empty:
                final_df = pd.concat([final_df, region_level_df], ignore_index=True)
            if not final_df.empty:
                final_df["ResourceType"] = "VPC"
                final_df["ResourceId"] = final_df["Target Entity"]
                output = final_df.to_dict(orient='records')
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def get_azure_advisor_recommendations(self, **kwargs):
        output = []
        try:
            service_account_id = self.execution_args['service_account_id']
            advisor_id = self.execution_args.get('RuleReference', {}).get('recommendationTypeId')
            if not advisor_id:
                raise Exception('Advisor id is a Mandatory parameter.')
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            policy_recommendation_def = db['policy_recommendation_definitions'].find_one({
                'api_reference.recommendationTypeId': advisor_id
            })
            if policy_recommendation_def:
                policy_recommendation_data = db['policy_recommendations'].find_one({
                    'service_account_id': service_account_id,
                    'definition_id': policy_recommendation_def['_id']})
                if policy_recommendation_data:
                    output = list(db['policy_resource_recommendations'].aggregate([
                        {
                            '$match': {
                                'status': 'open',
                                'recommendation_id': policy_recommendation_data['_id']
                            }
                        },
                        {
                            '$project': {
                                '_id': 0,
                                'ResourceId': "$resource_id",
                                'ResourceName': "$resource_name",
                                'ResourceType': "$resource_type"
                            }
                        }
                    ], cursor={}))
            return output, len(output)
        except Exception as e:
            raise Exception(str(e))

    def check_disk_encryption_gcp(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    try:
                        request = compute.disks().list(project=project_id, zone=zone).execute()
                        if request.get('items'):
                            while True:
                                total_results = request['items']
                                for each_resource in total_results:
                                    evaluated_resources += 1
                                    if not each_resource.get('diskEncryptionKey'):
                                        output.append(OrderedDict(ResourceId=each_resource.get('id'),
                                                                  ResourceName=each_resource.get('name'),
                                                                  ResourceType='Compute_Engine'))
                                if request.get("nextPageToken", ""):
                                    request = compute.disks().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken", "")).execute()
                                else:
                                    break
                    except Exception as e:
                        if "Invalid JWT Signature." in str(e):
                            continue
                        else:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_old_volume_snapshots(self, **kwargs):
        output = []
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            days_to_check = int(self.execution_args['args'].get('days'))
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                response = run_aws_operation(
                    credentials,
                    'ec2',
                    'describe_snapshots',
                    region_name=region,
                    operation_args={
                        'Filters': [
                            {
                                'Name': 'status',
                                'Values': ['completed'],
                            }
                        ],
                        'OwnerIds': []
                    },
                    response_key='Snapshots'
                )
                ref_check_date_time = datetime.utcnow() - timedelta(days=days_to_check)
                for snapshot in response:
                    evaluated_resources += 1
                    if snapshot.get("StartTime").replace(tzinfo=None) < ref_check_date_time.replace(tzinfo=None):
                        output.append(OrderedDict(
                            ResourceId=snapshot.get('SnapshotId', ''),
                            ResourceName=snapshot.get('SnapshotId', ''),
                            ResourceType='EC2',
                        ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_security_group_port_violation(self, **kwargs):
        output = []
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            port_to_check = self.execution_args['args'].get('port')
            for region in regions:
                response = run_aws_operation(
                    credentials,
                    'ec2',
                    'describe_security_groups',
                    region_name=region,
                    response_key='SecurityGroups'
                )
                for security_group in response:
                    evaluated_resources += 1
                    condition_flag = []
                    for ip_permission in security_group.get('IpPermissions', []):
                        if any(x.get('CidrIp') == '0.0.0.0/0' for x in ip_permission.get('IpRanges', [{}])):
                            if port_to_check == ip_permission.get('FromPort') == ip_permission.get('ToPort'):
                                condition_flag.append(True)
                    if not any(condition_flag):
                        output.append(OrderedDict(
                            ResourceId=security_group.get('GroupId', ""),
                            ResourceName=security_group.get('GroupName', ""),
                            ResourceType='EC2',
                        ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def cmn_aws_transfer_server_key_check(self, key_to_check, absent_value_to_check=None):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            if absent_value_to_check is None:
                absent_value_to_check = self.execution_args['args'].get('protocol', None)
            for region in regions:
                try:
                    list_response = run_aws_operation(
                        credentials,
                        'transfer',
                        'list_servers',
                        region_name=region,
                        response_key='Servers')
                except Exception as e:
                    raise Exception('Permission Denied or Region is not enabled to access resource. Error {}'.format(
                        str(e)))
                for server_id in [s.get('ServerId') for s in list_response if s.get('ServerId')]:
                    evaluated_resources += 1
                    server_details = run_aws_operation(
                        credentials,
                        'transfer',
                        'describe_server',
                        region_name=region,
                        operation_args={
                            'ServerId': server_id})

                    check_key = AccessNestedDict(server_details)
                    if not check_key.get(key_to_check) or (
                            absent_value_to_check and absent_value_to_check not in check_key.get(key_to_check, [])):
                        output.append(
                            OrderedDict(
                                ResourceId=server_id,
                                ResourceName=server_id,
                                Resource='Data_Transfer'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def cmn_aws_fsx_file_system_key_check(self, key_to_check, file_sys_type):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    fsx_response = run_aws_operation(
                        credentials,
                        'fsx',
                        'describe_file_systems',
                        region_name=region,
                        response_key='FileSystems')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for filesystem in fsx_response:
                    evaluated_resources += 1
                    if filesystem.get('FileSystemType') == file_sys_type:
                        if not filesystem.get(key_to_check):
                            output.append(
                                OrderedDict(
                                    ResourceId=filesystem.get('FileSystemId', ''),
                                    ResourceName=filesystem.get('FileSystemId', ''),
                                    Resource='AWS_Elastic_Filesystem'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_sagemaker_network_isolation_enabled_for_training_jobs(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    sage_response = run_aws_operation(
                        credentials,
                        'sagemaker',
                        'list_training_jobs',
                        region_name=region,
                        response_key='TrainingJobSummaries')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for training_job in sage_response:
                    evaluated_resources += 1
                    training_response = run_aws_operation(
                        credentials,
                        'sagemaker',
                        'describe_training_job',
                        operation_args={
                            'TrainingJobName': training_job.get('TrainingJobName', '')},
                        region_name=region)
                    if not training_response.get('EnableNetworkIsolation'):
                        output.append(
                            OrderedDict(
                                ResourceId=training_job.get('TrainingJobName', ''),
                                ResourceName=training_job.get('TrainingJobName', ''),
                                Resource='Amazon_SageMaker'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_sagemaker_tagging_exists(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    sage_response = run_aws_operation(
                        credentials,
                        'sagemaker',
                        'list_notebook_instances',
                        region_name=region,
                        response_key='NotebookInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for instance in sage_response:
                    evaluated_resources += 1
                    list_tags = run_aws_operation(
                        credentials,
                        'sagemaker',
                        'list_tags',
                        region_name=region,
                        operation_args={
                            'ResourceArn': instance.get('NotebookInstanceArn', '')},
                        response_key='Tags')
                    for tag in list_tags:
                        if not tag.get('Key'):
                            output.append(
                                OrderedDict(
                                    ResourceId=instance.get('NotebookInstanceArn', ''),
                                    ResourceName=instance.get('NotebookInstanceName', ''),
                                    Resource='Amazon_SageMaker'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cw_metrics_threshold_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_name = self.execution_args.get("service_account_name")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            list_metrics = self.execution_args['args'].get('list_metrics', '').split(',')
            for region in regions:
                for cloudwatch_metrics in list_metrics:
                    cloudwatch_metrics = cloudwatch_metrics.strip()
                    cloudwatch_response = run_aws_operation(
                        credentials,
                        'cloudwatch',
                        'describe_alarms_for_metric',
                        region_name=region,
                        operation_args={
                            'MetricName': cloudwatch_metrics,
                            'Namespace': service_account_name})

                    for alarm in cloudwatch_response.get('MetricAlarms', []):
                        evaluated_resources += 1
                        if not alarm.get('AlarmName', {}).get('Threshold'):
                            output.append(
                                OrderedDict(
                                    ResourceId=alarm.get('AlarmName', ''),
                                    ResourceName=alarm.get('AlarmName', ''),
                                    ResourceType='Cloudwatch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_fsx_fs_date_at_rest_encrypted_with_kms_cmks(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            file_sys_arg = self.execution_args['args'].get('file_system')
            alias_name_arg = self.execution_args['args'].get('alias_name')
            for region in regions:
                try:
                    fsx_response = run_aws_operation(
                        credentials,
                        'fsx',
                        'describe_file_systems',
                        region_name=region,
                        response_key='FileSystems')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for filesystem in fsx_response:
                    evaluated_resources += 1
                    if filesystem.get('FileSystemType') == file_sys_arg:
                        kms_list_aliases = run_aws_operation(
                            credentials,
                            'kms',
                            'list_aliases',
                            region_name=region,
                            operation_args={
                                'KeyId': filesystem.get('KmsKeyId')},
                            response_key='Aliases')
                        for kms_list_alias in kms_list_aliases:
                            if kms_list_alias.get('AliasName') == alias_name_arg:
                                output.append(
                                    OrderedDict(
                                        ResourceId=filesystem.get('FileSystemId', ''),
                                        ResourceName=filesystem.get('FileSystemId', ''),
                                        Resource='AWS_Elastic_Filesystem'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_fsx_fs_client_vpc_security_group_rules_exists(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    fsx_response = run_aws_operation(
                        credentials,
                        'fsx',
                        'describe_file_systems',
                        region_name=region,
                        response_key='FileSystems')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for filesystem in fsx_response:
                    if filesystem.get('FileSystemType') == self.execution_args['args'].get('file_system'):
                        evaluated_resources += 1
                        network_response = run_aws_operation(
                            credentials,
                            'ec2',
                            'describe_network_interfaces',
                            region_name=region,
                            operation_args={
                                'NetworkInterfaceIds': filesystem.get('NetworkInterfaceIds', [])},
                            response_key='NetworkInterfaces')
                        for network_info in network_response:
                            for sg_id in network_info.get('Groups', []):
                                if not sg_id.get('GroupId'):
                                    output.append(
                                        OrderedDict(
                                            ResourceId=filesystem.get('FileSystemId', ''),
                                            ResourceName=filesystem.get('FileSystemId', ''),
                                            Resource='AWS_Elastic_Filesystem'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_fsx_tagging_exists_for_fs(self, **kwargs):
        return self.cmn_aws_fsx_file_system_key_check(
            key_to_check='Tags',
            file_sys_type=self.execution_args['args'].get('file_system', None))

    def aws_transfer_server_tag_exists(self, **kwargs):
        return self.cmn_aws_transfer_server_key_check(key_to_check='Server.Tags')

    def aws_transfer_protocol_enabled(self, **kwargs):
        return self.cmn_aws_transfer_server_key_check(
            key_to_check='Server.Protocols',
            absent_value_to_check=self.execution_args['args'].get('protocol', None))

    def aws_transfer_server_endpoint_present_in_vpc(self, **kwargs):
        return self.cmn_aws_transfer_server_key_check(key_to_check='EndpointDetails')

    def aws_sg_virtual_tapes_encrypted_by_kms_cmks(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    storage_gateway_response = run_aws_operation(
                        credentials,
                        'storagegateway',
                        'list_tapes',
                        region_name=region,
                        response_key='TapeInfos')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                gateways_arn = [t.get('GatewayARN', '') for t in storage_gateway_response]
                tapes_arn = [t.get('TapeARN', '') for t in storage_gateway_response]
                evaluated_resources += 1
                if any(tapes_arn):
                    tapes_response = run_aws_operation(
                        credentials,
                        'storagegateway',
                        'describe_tapes',
                        region_name=region,
                        operation_args={
                            'GatewayARN': gateways_arn,
                            'TapeARNs': tapes_arn},
                        response_key='Tapes')
                    for tape in tapes_response:
                        if not tape.get('KMSKey'):
                            output.append(
                                OrderedDict(
                                    ResourceId=tape.get('TapeARN', ''),
                                    ResourceName=tape.get('TapeARN', ''),
                                    Resource='Storage_Gateway'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_sg_volumes_encrypted_using_kms_cmks(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    storage_gateway_response = run_aws_operation(
                        credentials,
                        'storagegateway',
                        'list_volumes',
                        region_name=region,
                        response_key='VolumeInfos')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                volumes_arn = [v.get('VolumeARN', '') for v in storage_gateway_response]
                evaluated_resources += 1
                if any(volumes_arn):
                    volumes_response = run_aws_operation(
                        credentials,
                        'storagegateway',
                        'describe_cached_iscsi_volumes',
                        region_name=region,
                        operation_args={
                            'VolumeARNs': volumes_arn
                        })
                    for volume_info in volumes_response.get('CachediSCSIVolumes', []):
                        if not volume_info.get('KMSKey'):
                            output.append(
                                OrderedDict(
                                    ResourceId=volume_info['VolumeId'],
                                    ResourceName=volume_info['VolumeARN'],
                                    Resource='Storage_Gateway'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_sg_file_share_key_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            key_to_check = self.execution_args['args'].get('key_to_check')
            for region in regions:
                try:
                    storage_gateway_response = run_aws_operation(
                        credentials,
                        'storagegateway',
                        'list_file_shares',
                        region_name=region,
                        response_key='FileShareInfoList')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                file_share_arn = [sg_resp.get('FileShareARN', '') for sg_resp in storage_gateway_response]
                evaluated_resources += 1

                if any(file_share_arn):
                    nfs_file_response = run_aws_operation(
                        credentials,
                        'storagegateway',
                        'describe_nfs_file_shares',
                        region_name=region,
                        operation_args={
                            "FileShareARNList": file_share_arn})

                    smb_file_response = run_aws_operation(
                        credentials,
                        'storagegateway',
                        'describe_smb_file_shares',
                        region_name=region,
                        operation_args={
                            "FileShareARNList": file_share_arn})

                    for fileshare in nfs_file_response.get('NFSFileShareInfoList', []) + smb_file_response.get(
                            'SMBFileShareInfoList', []):
                        if not fileshare.get(key_to_check):
                            output.append(
                                OrderedDict(
                                    ResourceId=fileshare.get('FileShareId', ''),
                                    ResourceName=fileshare.get('FileShareARN', ''),
                                    Resource='Storage_Gateway'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cw_metrics_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_name = self.execution_args.get("service_account_name")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                for cloudwatch_metric in self.execution_args['args'].get('list_metrics').split(','):
                    evaluated_resources += 1
                    cloudwatch_metric = cloudwatch_metric.strip()
                    cloudwatch_response = run_aws_operation(
                        credentials,
                        'cloudwatch',
                        'describe_alarms_for_metric',
                        region_name=region,
                        operation_args={
                            'MetricName': cloudwatch_metric,
                            'Namespace': service_account_name})
                    if not cloudwatch_response.get('MetricAlarms', []):
                        output.append(
                            OrderedDict(
                                ResourceId=cloudwatch_metric,
                                ResourceName=cloudwatch_metric,
                                Resource='Cloudwatch'))
                return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_compute_project_wide_ssh_keys_allowed(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    try:
                        request = compute.instances().list(project=project_id, zone=zone).execute()
                        while True:
                            ssh_key = dict()
                            for vm in request.get('items', []):
                                evaluated_resources += 1
                                for block_project_wise_ssh_key in vm.get("metadata", {}).get('items', {}):
                                    ssh_key[block_project_wise_ssh_key.get("key")] = block_project_wise_ssh_key.get(
                                        "value")
                                if "block-project-ssh-keys" not in ssh_key:
                                    output.append(
                                        OrderedDict(ResourceId=vm.get('id'),
                                                    ResourceName=vm.get('name'),
                                                    ResourceType='Compute_Engine'))
                                elif "block-project-ssh-keys" in ssh_key and ssh_key[
                                    "block-project-ssh-keys"] != "true":
                                    output.append(
                                        OrderedDict(ResourceId=vm.get('id'),
                                                    ResourceName=vm.get('name'),
                                                    ResourceType='Compute_Engine'))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                    except Exception as e:
                        raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_compute_secure_boot_disabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    try:
                        request = compute.instances().list(project=project_id, zone=zone).execute()
                        while True:
                            for vm in request.get('items', []):
                                evaluated_resources += 1
                                if not (vm.get("shieldedInstanceConfig", {}).get("enableSecureBoot", False) and
                                        vm.get("shieldedInstanceConfig", {}).get("enableVtpm", False) and
                                        vm.get("shieldedInstanceConfig", {}).get("enableIntegrityMonitoring", False)):
                                    output.append(
                                        OrderedDict(ResourceId=vm.get('id'),
                                                    ResourceName=vm.get('name'),
                                                    ResourceType='VM_Instances'))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                    except Exception as e:
                        raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_check_disks_are_encrypted(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_volumes',
                        region_name=region,
                        response_key='Volumes')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for volume in ec2_response:
                    evaluated_resources += 1
                    if not volume.get('Encrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=volume.get('VolumeId', ''),
                                ResourceName=volume.get('VolumeId', ''),
                                ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_compute_serial_ports_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    try:
                        request = compute.instances().list(project=project_id, zone=zone).execute()
                        while True:
                            for vm in request.get('items', []):
                                evaluated_resources += 1
                                if vm.get("metadata", {}).get("items"):
                                    item_dict = dict()
                                    for key_value in vm["metadata"]["items"]:
                                        item_dict[key_value.get('key')] = key_value.get('value')
                                    if "serial-port-enable" in item_dict and item_dict["enable-oslogin"] == "True":
                                        output.append(
                                            OrderedDict(ResourceId=vm.get('id'),
                                                        ResourceName=vm.get('name'),
                                                        ResourceType='VM_Instances'))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                    except Exception as e:
                        raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_security_group_unrestricted_access(self, default_handler=None):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region,
                        operation_args=default_handler,
                        response_key='SecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for sg in ec2_response:
                    evaluated_resources += 1
                    if sg.get('GroupName'):
                        output.append(
                            OrderedDict(
                                ResourceId=sg.get('GroupName', ''),
                                ResourceName=sg.get('GroupName', ''),
                                ResourceType='SecurityGroups'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_disk_encrypted_without_csek(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    try:
                        request = compute.instances().list(project=project_id, zone=zone).execute()
                        while True:
                            for vm in request.get('items', []):
                                vm_name = vm.get("name")
                                disks_list = vm.get("disks")
                                disk_name_list = list()
                                for disks in disks_list:
                                    disk_name_list.append(disks.get('source').split('/')[-1])
                                for disk in disk_name_list:
                                    evaluated_resources += 1
                                    try:
                                        disk_object = compute.disks().get(project=project_id, zone=zone,
                                                                          disk=disk).execute()
                                        if not disk_object.get("diskEncryptionKey"):
                                            output.append(
                                                OrderedDict(ResourceId=disk_object.get('id'),
                                                            ResourceName=disk,
                                                            ResourceInstanceName=vm_name,
                                                            ResourceType='Disks'))
                                        elif not disk_object.get("diskEncryptionKey").get("sha256"):
                                            output.append(
                                                OrderedDict(ResourceId=disk_object.get('id'),
                                                            ResourceName=disk,
                                                            ResourceInstanceName=vm_name,
                                                            ResourceType='Disks'))
                                    except Exception as e:
                                        raise Exception(str(e))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                    except Exception as e:
                        raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_security_group_unrestricted_cifs_access(self, **kwargs):
        try:
            handler = dict(Filters=[
                {
                    'Name': 'ip-permission.from-port',
                    'Values': [
                        '445'
                    ]
                },
                {
                    'Name': 'ip-permission.to-port',
                    'Values': [
                        '445'
                    ]
                },
                {
                    'Name': 'ip-permission.cidr',
                    'Values': [
                        '0.0.0.0/0'
                    ]
                }
            ])
            output, evaluated_resources = self.aws_ec2_security_group_unrestricted_access(default_handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_security_group_unrestricted_dns_access(self, **kwargs):
        try:
            handler = dict(Filters=[
                {
                    'Name': 'ip-permission.from-port',
                    'Values': [
                        '53'
                    ]
                },
                {
                    'Name': 'ip-permission.to-port',
                    'Values': [
                        '53'
                    ]
                },
                {
                    'Name': 'ip-permission.cidr',
                    'Values': [
                        '0.0.0.0/0',
                    ]
                },
            ])
            output, evaluated_resources = self.aws_ec2_security_group_unrestricted_access(default_handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_security_group_unrestricted_telnet_access(self, **kwargs):
        try:
            handler = dict(Filters=[
                {
                    'Name': 'ip-permission.from-port',
                    'Values': [
                        '23'
                    ]
                },
                {
                    'Name': 'ip-permission.to-port',
                    'Values': [
                        '23'
                    ]
                },
                {
                    'Name': 'ip-permission.cidr',
                    'Values': [
                        '0.0.0.0/0'
                    ]
                }
            ])
            output, evaluated_resources = self.aws_ec2_security_group_unrestricted_access(default_handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_security_group_unrestricted_ftp_access(self, **kwargs):
        try:
            handler = dict(Filters=[
                {
                    'Name': 'ip-permission.from-port',
                    'Values': [
                        '21'
                    ]
                },
                {
                    'Name': 'ip-permission.to-port',
                    'Values': [
                        '21'
                    ]
                },
                {
                    'Name': 'ip-permission.cidr',
                    'Values': [
                        '0.0.0.0/0'
                    ]
                }
            ])
            output, evaluated_resources = self.aws_ec2_security_group_unrestricted_access(default_handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_security_group_unrestricted_icmp_access(self, **kwargs):
        try:
            handler = dict(Filters=[
                {
                    'Name': 'ip-permission.protocol',
                    'Values': [
                        'icmp'
                    ]
                },
                {
                    'Name': 'ip-permission.cidr',
                    'Values': [
                        '0.0.0.0/0'
                    ]
                }
            ])
            output, evaluated_resources = self.aws_ec2_security_group_unrestricted_access(default_handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_efs_encryption(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    efs_response = run_aws_operation(
                        credentials,
                        'efs',
                        'describe_file_systems',
                        region_name=region,
                        response_key='FileSystems')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for efs in efs_response:
                    evaluated_resources += 1
                    if not efs.get('Encrypted'):
                        output.append(
                            OrderedDict(
                                ResourceId=efs['FileSystemId'],
                                ResourceName=efs['FileSystemId'],
                                ResourceType='FileSystems'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_full_api_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    try:
                        request = compute.instances().list(project=project_id, zone=zone).execute()
                        while True:
                            for vm in request.get('items', []):
                                evaluated_resources += 1
                                if vm.get("serviceAccounts"):
                                    email = vm.get("serviceAccounts")[0].get("email").split('@')[1]
                                    if email == "developer.gserviceaccount.com" and \
                                            vm.get("serviceAccounts")[0].get("scopes")[
                                                0] == "https://www.googleapis.com/auth/cloud-platform":
                                        output.append(
                                            OrderedDict(ResourceId=vm.get('id'),
                                                        ResourceName=vm.get('name'),
                                                        ResourceType='VM_Instances'))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                    except Exception as e:
                        raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_lambda_function_exposed(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            operation_args1 = {}
            credentials = self.execution_args['auth_values']
            operation_args = dict(FunctionVersion='ALL')
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    try:
                        operation_args1.update(
                            FunctionName=function['FunctionName'])
                        lambda_policy = run_aws_operation(
                            credentials,
                            'lambda',
                            'get_policy',
                            region_name=region,
                            operation_args=operation_args1)
                        policy = json.loads(lambda_policy.get('Policy'))
                        for statement in policy.get('Statement'):
                            if statement.get('Effect') == 'Allow':
                                for key, value in statement.get('Principal').items():
                                    if key == 'AWS' and value == '*':
                                        output.append(
                                            OrderedDict(
                                                ResourceId=function.get('FunctionName', ''),
                                                ResourceName=function.get('FunctionName', ''),
                                                ResourceType='Lambda'))
                    except ClientError as e:
                        if 'ResourceNotFoundException' in str(e):
                            continue
                        else:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_ip_forwarding_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    try:
                        request = compute.instances().list(project=project_id, zone=zone).execute()
                        while True:
                            for vm in request.get('items', []):
                                evaluated_resources += 1
                                if vm.get('canIpForward'):
                                    output.append(
                                        OrderedDict(ResourceId=vm.get('id'),
                                                    ResourceName=vm.get('name'),
                                                    ResourceType='VM_Instances'))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                    except Exception as e:
                        raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_route53_auto_renew(self, **kwargs):
        try:
            output = list()
            operation_args = {}
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    route53_domain = run_aws_operation(
                        credentials,
                        'route53domains',
                        'list_domains',
                        region_name=region,
                        response_key='Domains')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in route53_domain:
                    evaluated_resources += 1
                    operation_args.update(DomainName=domains['DomainName'])
                    domain_info = run_aws_operation(
                        credentials,
                        'route53domains',
                        'get_domain_detail',
                        region_name=region,
                        operation_args=operation_args)
                    if not domain_info.get('AutoRenew'):
                        output.append(
                            OrderedDict(
                                ResourceId=domains['DomainName'],
                                ResourceName=domains['DomainName'],
                                ResourceType='Domains'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elb_access_logging(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerName=elb['LoadBalancerName'])
                    elb_info = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancer_attributes',
                        region_name=region,
                        operation_args=operation_args)
                    if not elb_info.get('LoadBalancerAttributes', {}).get('AccessLog', {}).get('Enabled'):
                        output.append(
                            OrderedDict(
                                ResourceId=elb['LoadBalancerName'],
                                ResourceName=elb['LoadBalancerName'],
                                ResourceType='Load_Balancers'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_lambda_service_without_deadletter_configuration(self, **kwargs):
        try:
            output = list()
            lambda_function_list = list()
            operation_args = {}
            operation_args1 = {}
            credentials = self.execution_args['auth_values']
            operation_args.update(FunctionVersion='ALL')
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    lambda_function_list.append(function['FunctionName'])
                    try:
                        operation_args1.update(
                            FunctionName=function['FunctionName'])
                        lambda_policy = run_aws_operation(
                            credentials,
                            'lambda',
                            'get_function_configuration',
                            region_name=region,
                            operation_args=operation_args1)
                        try:
                            if not lambda_policy['DeadLetterConfig']['TargetArn']:
                                output.append(
                                    OrderedDict(
                                        ResourceId=function['FunctionName'],
                                        ResourceName=function['FunctionName'],
                                        ResourceType='lambda'))
                        except Exception as e:
                            if 'DeadLetterConfig' in str(e):
                                output.append(
                                    OrderedDict(
                                        ResourceId=function['FunctionName'],
                                        ResourceName=function['FunctionName'],
                                        ResourceType='lambda'))
                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code")
                        if error_code == 'ResourceNotFoundException':
                            pass
            return output, len(lambda_function_list)
        except Exception as e:
            raise Exception(str(e))

    def check_os_login_disabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                try:
                    describe_project = compute.projects().get(project=project_id).execute()
                    os_login_flag = False
                    for item_dict in describe_project.get('commonInstanceMetadata', {}).get('items'):
                        if "enable-oslogin" == item_dict.get('key') and item_dict.get('values') != "FALSE":
                            os_login_flag = True
                            break
                    for zone in zones:
                        list_vm = list()
                        instances_list = compute.instances().list(project=project_id, zone=zone).execute()
                        list_vm = instances_list.get("items", [])
                        while True:
                            for instance in list_vm:
                                evaluated_resources += 1
                                if instance.get("metadata", {}).get("items") is not None:
                                    item_dict = dict()
                                    for key_value in instance.get("metadata").get("items"):
                                        item_dict[key_value.get('key')] = key_value.get('value')
                                    if "enable-oslogin" not in item_dict:
                                        if os_login_flag == False:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get('id'),
                                                            ResourceName=instance.get('name'),
                                                            ResourceType='VM_Instances'))
                                    elif "enable-oslogin" in item_dict and item_dict["enable-oslogin"] == "FALSE":
                                        output.append(
                                            OrderedDict(ResourceId=instance.get('id'),
                                                        ResourceName=instance.get('name'),
                                                        ResourceType='VM_Instances'))
                            if instances_list.get("nextPageToken"):
                                instances_list = compute.instances().list(project=project_id, zone=zone,
                                                                          pageToken=instances_list.get(
                                                                              "nextPageToken")).execute()
                            else:
                                break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_instances_without_termination_protection(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for reservation in ec2_instance_response:
                    for instance in reservation['Instances']:
                        evaluated_resources += 1
                        operation_args.update(
                            InstanceId=instance['InstanceId'],
                            Attribute='disableApiTermination')
                        try:
                            ec2_info = run_aws_operation(
                                credentials,
                                'ec2',
                                'describe_instance_attribute',
                                region_name=region,
                                operation_args=operation_args)
                            if not ec2_info.get('DisableApiTermination', {}).get('Value'):
                                output.append(
                                    OrderedDict(
                                        ResourceId=instance['InstanceId'],
                                        ResourceName=instance['InstanceId'],
                                        Resource='ec2'))
                        except Exception as e:
                            raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_instance_using_public_ip_address(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    instances_list = compute.instances().list(project=project_id, zone=zone).execute()
                    while True:
                        for instance in instances_list.get("items", []):
                            evaluated_resources += 1
                            networkinterface_list = instance.get('networkInterfaces', [])
                            accessconfigs_list = networkinterface_list[0].get('accessConfigs', [])
                            for accessconfigs in accessconfigs_list:
                                if "natIP" in accessconfigs.keys():
                                    output.append(
                                        OrderedDict(ResourceId=instance.get('id'),
                                                    ResourceName=instance.get('name'),
                                                    ResourceType='VM_Instances'))
                        if instances_list.get("nextPageToken"):
                            instances_list = compute.instances().list(project=project_id, zone=zone,
                                                                      pageToken=instances_list.get(
                                                                          "nextPageToken")).execute()
                        else:
                            break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_volumes_not_having_snapshot(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            days_before = (datetime.now() - timedelta(days=7))
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(Filters=[
                        {
                            'Name': 'status',
                            'Values': [
                                'completed'
                            ]
                        }
                    ], OwnerIds=['self'])
                    ebs_volumes_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_snapshots',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='Snapshots')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for snapshot in ebs_volumes_response:
                    evaluated_resources += 1
                    if str(days_before) >= snapshot['StartTime'].strftime("%Y-%m-%dT%H:%M:%S"):
                        output.append(
                            OrderedDict(
                                ResourceId=snapshot['SnapshotId'],
                                ResourceName=snapshot['SnapshotId'],
                                ResourceType="EBS"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_default_vpc_network_used(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                network_list = compute.networks().list(project=project_id).execute()
                while True:
                    for network in network_list.get("items", []):
                        if network.get("name") == "default":
                            output.append(
                                OrderedDict(ResourceId=network.get('id'),
                                            ResourceName=project_id,
                                            ResourceType='Network'))
                            break
                    if network_list.get("nextPageToken"):
                        network_list = compute.networks().list(project=project_id,
                                                               pageToken=network_list.get("nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_ami_encryption(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(
                        Owners=[
                            'self'
                        ])
                    total_images = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_images',
                        operation_args=operation_args,
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for image_data in total_images['Images']:
                    evaluated_resources += 1
                    for data in image_data.get('BlockDeviceMappings', []):
                        if not data.get('Ebs', {}).get('Encrypted'):
                            output.append(
                                OrderedDict(
                                    ResourceId=image_data['ImageId'],
                                    ResourceName=image_data['ImageId'],
                                    ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_instance_using_older_generation_instance_type(self):
        try:
            output = list()
            evaluated_resources = 0
            previous_generation_instance_list = [
                'm1', 'm2', 'm3', 'c1', 'c2', 'c3', 'g2', 'cr1', 'r3', 'i2', 'hs1', 't1'
            ]
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for data in ec2_instance:
                    for instance in data['Instances']:
                        evaluated_resources += 1
                        instance_type = instance['InstanceType'].split('.')[0]
                        if instance_type in previous_generation_instance_list:
                            output.append(
                                OrderedDict(
                                    ResourceId=instance['InstanceId'],
                                    ResourceName=instance['InstanceId'],
                                    ResourceType='Instances'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_instance_using_older_generation_instance_type(self):
        try:
            output = list()
            evaluated_resources = 0
            previous_generation_instance_list = [
                'm1', 'm2', 'm3', 'c1', 'c2', 'c3', 'g2', 'cr1', 'r3', 'i2', 'hs1', 't1']
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_clusters = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for data in db_clusters:
                    evaluated_resources += 1
                    db_instance = str(data['DBInstanceClass']).split('.')[1]
                    if db_instance in previous_generation_instance_list:
                        output.append(
                            OrderedDict(
                                ResourceId=data['DBInstanceIdentifier'],
                                ResourceName=data['DBInstanceIdentifier'],
                                ResourceType='DBInstances'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_auto_sql_instance_backup_disabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as compute:
                try:
                    request = compute.instances().list(project=project_id).execute()
                    while True:
                        for sql_instance in request.get('items', []):
                            evaluated_resources += 1
                            if not sql_instance.get('settings', {}).get('backupConfiguration', {}).get('enabled'):
                                output.append(
                                    OrderedDict(ResourceId=sql_instance.get('name'),
                                                ResourceName=sql_instance.get('name'),
                                                ResourceType='SQL_Instances'))
                        if request.get("nextPageToken"):
                            request = compute.instances().list(project=project_id,
                                                               pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_multi_availability_zone_not_enabled_instance(self):
        try:
            output = list()
            evaluated_resources = 0
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_clusters = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_clusters',
                        region_name=region,
                        response_key='DBClusters')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for data in db_clusters:
                    evaluated_resources += 1
                    if not data['MultiAZ']:
                        output.append(
                            OrderedDict(
                                ResourceId=data['DatabaseName'],
                                ResourceName=data['DatabaseName'],
                                Resource='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ebs_volume_is_unattached(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    operation_args.update(
                        Filters=[{'Name': 'status', 'Values': ['available']}])
                    ebs_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_volumes',
                        region_name=region,
                        operation_args=operation_args,
                        response_key='Volumes')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for volume in ebs_response:
                    evaluated_resources += 1
                    if volume['VolumeId']:
                        output.append(
                            OrderedDict(
                                ResourceId=volume['VolumeId'],
                                ResourceName=volume['VolumeId'],
                                Resource='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_internet_gateway_authorized_vpc_only(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args.get('regions', {})]
            authorized_vpc = list(map(str.strip, self.execution_args["args"]['authorized_vpc'].split(',')))
            for region in regions:
                try:
                    nat_gateway = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_nat_gateways',
                        region_name=region,
                        response_key='NatGateways')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for vpc in nat_gateway:
                    evaluated_resources += 1
                    if vpc['VpcId'] not in authorized_vpc:
                        output.append(
                            OrderedDict(
                                ResourceId=vpc['VpcId'],
                                ResourceName=vpc['VpcId'],
                                ResourceType='ec2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_network_load_balancer_security_policy(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        policy_list = [
            'ELBSecurityPolicy-2016-08',
            'ELBSecurityPolicy-TLS-1-1-2017-01',
            'ELBSecurityPolicy-FS-2018-06',
            'ELBSecurityPolicy-TLS-1-2-Ext-2018-06']
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancers')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerArn=elb['LoadBalancerArn'])
                    elb_listener_info = run_aws_operation(
                        credentials,
                        'elbv2',
                        'describe_listeners',
                        operation_args=operation_args,
                        response_key='Listeners')
                    for elb_listener in elb_listener_info:
                        if not (
                                'SslPolicy' in elb_listener and elb_listener['SslPolicy'] in policy_list):
                            output.append(
                                OrderedDict(
                                    ResourceId=elb['LoadBalancerName'],
                                    ResourceName=elb['LoadBalancerName'],
                                    ResourceType="elb"))
            return output, evaluated_resources

        except Exception as e:
            raise Exception(e.message)

    def aws_webtier_elb_listener_security(self, **kwargs):
        try:
            output = list()
            evaluated_resources = 0
            operation_args = {}
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            web_tier_tag_key = self.execution_args.get("web_tier_tag")["key"]
            web_tier_tag_value = self.execution_args.get("web_tier_tag")[
                "value"]
            for region in regions:
                try:
                    elb_response = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_load_balancers',
                        region_name=region,
                        response_key='LoadBalancerDescriptions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))

                for elb in elb_response:
                    evaluated_resources += 1
                    operation_args.update(
                        LoadBalancerNames=[elb['LoadBalancerName']])
                    tag_info = run_aws_operation(
                        credentials,
                        'elb',
                        'describe_tags',
                        operation_args=operation_args)
                    for elb_tag in tag_info['TagDescriptions']:
                        for tag in elb_tag['Tags']:
                            if tag['Value'] == web_tier_tag_value and tag['Key'] == web_tier_tag_key:
                                if elb['ListenerDescriptions']:
                                    for listener_descriptions in elb['ListenerDescriptions']:
                                        if not listener_descriptions['Listener']['Protocol'] in [
                                            'HTTPS', 'SSL']:
                                            output.append(
                                                OrderedDict(
                                                    ResourceId=elb['LoadBalancerName'],
                                                    ResourceName=elb['LoadBalancerName'],
                                                    ResourceType='elb'))
                                else:
                                    output.append(
                                        OrderedDict(
                                            ResourceId=elb['LoadBalancerName'],
                                            ResourceName=elb['LoadBalancerName'],
                                            ResourceType='elb'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_using_iam_role_more_than_one_lambda_function(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        credentials = self.execution_args['auth_values']
        try:
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    operation_args.update(
                        FunctionName=function['FunctionName'])
                    function_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'get_function',
                        region_name=region,
                        operation_args=operation_args)
                    role = function_response.get('Configuration', {}).get('Role')
                    if role != " ":
                        output.append(
                            OrderedDict(
                                ResourceId=function['FunctionName'],
                                ResourceName=function['FunctionName'],
                                ResourceType='lambda'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ec2_securitygroup_with_bastionssh(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            allowed_host = self.execution_args['args']['allowed_host']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    security_groups = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_security_groups',
                        region_name=region,
                        response_key='SecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups['SecurityGroups']:
                    evaluated_resources += 1
                    security_group_compliant = True
                    for security_group_ippermissions in security_group['IpPermissions']:
                        if (
                                security_group_ippermissions['IpProtocol']) != '-1':
                            if (security_group_ippermissions['FromPort'] == 22
                                    and security_group_ippermissions['ToPort'] == 22):
                                for ip_address in security_group_ippermissions['IpRanges']:
                                    if ip_address['CidrIp'] not in allowed_host:
                                        security_group_compliant = False
                    if not security_group_compliant:
                        output.append(
                            OrderedDict(
                                ResourceId=security_group['GroupId'],
                                ResourceName=security_group['GroupId'],
                                ResourceType="SecurityGroup"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_ecs_no_public_ip_assigned(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        operation_args_1 = {}
        chunk_size = 10
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ecs_response = run_aws_operation(
                        credentials,
                        'ecs',
                        'list_clusters',
                        region_name=region,
                        response_key='clusterArns')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for cluster_arn in ecs_response:
                    operation_args.update(
                        cluster=cluster_arn)
                    services_list = run_aws_operation(
                        credentials,
                        'ecs',
                        'list_services',
                        operation_args,
                        region_name=region,
                        response_key='serviceArns')
                    services_list = [services_list[i:i + chunk_size] for i in range(0, len(services_list), chunk_size)]
                    for service in services_list:
                        evaluated_resources += 1
                        operation_args_1.update(
                            cluster=cluster_arn,
                            services=service)
                        services_response = run_aws_operation(
                            credentials,
                            'ecs',
                            'describe_services',
                            operation_args_1,
                            region_name=region,
                            response_key='services')
                        for service in services_response['services']:
                            public_ip = service.get('networkConfiguration', {}).get('awsvpcConfiguration', {}).get(
                                'assignPublicIp')
                            if public_ip == "DISABLED" or public_ip == None:
                                output.append(
                                    OrderedDict(
                                        ResourceId=service['serviceArn'],
                                        ResourceName=service['serviceName'],
                                        ResourceType='ECS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elasticsearch_minimum_version(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            elasticsearch_minimum_version = self.execution_args['args']['elasticsearch_minimum_version']
            domain_names = list()
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'list_domain_names',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response['DomainNames']:
                    domain_names.append(domains['DomainName'])
                operation_args.update(
                    DomainNames=domain_names)
                esresponse = run_aws_operation(
                    credentials,
                    'es',
                    'describe_elasticsearch_domains',
                    operation_args=operation_args,
                    region_name=region)
                for domain_status in esresponse['DomainStatusList']:
                    evaluated_resources += 1
                    if 'OpenSearch' not in domain_status['ElasticsearchVersion']:
                        if domain_status['ElasticsearchVersion'] < elasticsearch_minimum_version:
                            output.append(
                                OrderedDict(
                                    ResourceId=domain_status['DomainName'],
                                    ResourceName=domain_status['DomainName'],
                                    ResourceType='ElasticSearch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_elasticsearch_encrypted_at_rest(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    es_response = run_aws_operation(
                        credentials,
                        'es',
                        'list_domain_names',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for domains in es_response['DomainNames']:
                    operation_args.update(DomainNames=domains['DomainName'])

                esresponse = run_aws_operation(
                    credentials,
                    'es',
                    'describe_elasticsearch_domains',
                    operation_args)
                for domain_status in esresponse['DomainStatusList']:
                    evaluated_resources += 1
                    if domain_status.get('EncryptionAtRestOptions', {}).get('Enabled') == False:
                        output.append(
                            OrderedDict(
                                ResourceId=domain_status['DomainName'],
                                ResourceName=domain_status['DomainName'],
                                ResourceType='es'))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_audit_dynamodb_pitr_enabled(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_response = run_aws_operation(
                        credentials,
                        'dynamodb',
                        'list_tables',
                        region_name=region,
                        response_key='TableNames')
                except Exception as e:
                    if "ResourceNotFoundError" in str(e):
                        continue
                for table in db_response:
                    operation_args.update(TableName=table)
                    evaluated_resources += 1
                    try:
                        backup_response = run_aws_operation(
                            credentials,
                            'dynamodb',
                            'describe_continuous_backups',
                            region_name=region,
                            operation_args=operation_args)
                        for info in backup_response['ContinuousBackupsDescription']:
                            if info.get('PointInTimeRecoveryDescription', {}).get(
                                    'PointInTimeRecoveryStatus') == 'DISABLED':
                                output.append(
                                    OrderedDict(
                                        ResourceId=table,
                                        ResourceName=table,
                                        ResourceType='DynamoDB'))
                    except Exception as e:
                        if "ResourceNotFoundError" in str(e):
                            continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_dynamodb_table_encryption_enabled(self, **kwargs):
        output = list()
        operation_args = {}
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get(
                "service_account_name")
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    db_response = run_aws_operation(
                        credentials,
                        'dynamodb',
                        'list_tables',
                        region_name=region,
                        response_key='TableNames')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for tables in db_response:
                    operation_args.update(TableName=tables)
                    evaluated_resources += 1
                    table_response = run_aws_operation(
                        credentials,
                        'dynamodb',
                        'describe_table',
                        region_name=region,
                        operation_args=operation_args)
                    try:
                        if table_response['SSEDescription']['Status'] == 'DISABLED':
                            output.append(
                                OrderedDict(
                                    ResourceId=tables,
                                    ResourceName=tables,
                                    Resource='dynamodb',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=service_account_name))
                    except Exception as e:
                        if "SSEDescription" in str(e):
                            output.append(
                                OrderedDict(
                                    ResourceId=tables,
                                    ResourceName=tables,
                                    Resource='dynamodb',
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=service_account_name))

            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_attach_policy_iam_roles_app_tier_ec2_instances(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            app_tier_tag = self.execution_args["app_tier_tag"]
            app_tier_tag_value = self.execution_args["app_tier_tag_value"]
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    ec2_instance_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region,
                        response_key='Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for ec2_reservations in ec2_instance_response:
                    for ec2_instance_info in ec2_reservations['Instances']:
                        evaluated_resources += 1
                        operation_args.update(
                            Filters=[
                                {
                                    'Name': 'resource-id',
                                    'Values': [
                                        ec2_instance_info['InstanceId'],
                                    ]
                                },
                            ]
                        )
                        ec2_tags = run_aws_operation(
                            credentials,
                            'ec2',
                            'describe_tags',
                            operation_args=operation_args,
                            region_name=region,
                            response_key='Tags')

                        for tag in ec2_tags:
                            if tag['Key'] != app_tier_tag and tag['Value'] != app_tier_tag_value:
                                output.append(
                                    OrderedDict(
                                        ResourceId=ec2_instance_info['InstanceId'],
                                        ResourceName=ec2_instance_info['InstanceId'],
                                        ResourceType="EC2"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def aws_instance_level_events_subscriptions(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_event_subscriptions',
                        region_name=region,
                        response_key='EventSubscriptionsList')

                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                evaluated_resources += 1
                db_instance_subscription = list(
                    filter(
                        lambda event_subscription: event_subscription['SourceType'] == 'db-instance',
                        rds_response))
                if len(db_instance_subscription) == 0:
                    output.append(
                        OrderedDict(
                            ResourceId=region,
                            ResourceName=region,
                            ResourceType='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(e.message)

    def gcp_audit_unrestricted_service_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            service = self.execution_args.get('args', {}).get("service")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                try:
                    networks = compute.networks().list(project=project_id).execute()
                    self_link_list = list()
                    while True:
                        for network in networks.get('items', []):
                            self_link_list.append(network.get("selfLink"))
                        try:
                            firewall_rules_list = compute.firewalls().list(project=project_id).execute()
                            for network_self_link in self_link_list:
                                firewall_rules = [rules for rules in firewall_rules_list.get("items", []) if
                                                  rules.get("network") == network_self_link]
                                output_rule_name_list = list()
                                for rule in firewall_rules:
                                    for data in services_protocol_port.get(service.lower(), []):
                                        protocol = list(data.keys())[0]
                                        port = data.get(protocol, "")
                                        if not rule.get("disabled") and rule.get("direction") == "INGRESS":
                                            if rule.get("sourceRanges")[0] == "0.0.0.0/0":
                                                if rule.get("allowed", [])[0].get("IPProtocol") == "all":
                                                    if rule["name"] not in output_rule_name_list:
                                                        output_rule_name_list.append(rule["name"])
                                                        output.append(
                                                            OrderedDict(ResourceId=rule['id'],
                                                                        ResourceName=rule['name'],
                                                                        ResourceType='Firewall'))
                                                elif ("ports" not in rule.get("allowed", [])[0] and
                                                      rule.get("allowed", [])[0].get(
                                                          "IPProtocol", "") == protocol):
                                                    if rule["name"] not in output_rule_name_list:
                                                        output_rule_name_list.append(rule["name"])
                                                        output.append(
                                                            OrderedDict(ResourceId=rule['id'],
                                                                        ResourceName=rule['name'],
                                                                        ResourceType='Firewall'))
                                                elif (rule.get("allowed", [])[0].get("IPProtocol", "") == protocol and
                                                      (rule.get("allowed", [])[0].get("ports", [])[0] == port or
                                                       rule.get("allowed", [])[0].get("ports", [])[0] == "0-65535")):
                                                    if rule["name"] not in output_rule_name_list:
                                                        output_rule_name_list.append(rule["name"])
                                                        output.append(
                                                            OrderedDict(ResourceId=rule['id'],
                                                                        ResourceName=rule['name'],
                                                                        ResourceType='Firewall'))
                                            else:
                                                if rule.get("allowed", [])[0].get("IPProtocol", "") == "all":
                                                    if rule["name"] not in output_rule_name_list:
                                                        output_rule_name_list.append(rule["name"])
                                                        output.append(
                                                            OrderedDict(ResourceId=rule['id'],
                                                                        ResourceName=rule['name'],
                                                                        ResourceType='Firewall'))
                                                elif ("ports" not in rule.get("allowed", [])[0] and
                                                      rule.get("allowed", [])[0].get("IPProtocol", "") == protocol):
                                                    if rule["name"] not in output_rule_name_list:
                                                        output_rule_name_list.append(rule["name"])
                                                        output.append(
                                                            OrderedDict(ResourceId=rule['id'],
                                                                        ResourceName=rule['name'],
                                                                        ResourceType='Firewall'))
                                                elif (rule.get("allowed", [])[0].get("IPProtocol", "") == protocol and
                                                      rule.get("allowed", [])[0].get("ports")[0] == "0-65535"):
                                                    if rule["name"] not in output_rule_name_list:
                                                        output_rule_name_list.append(rule["name"])
                                                        output.append(
                                                            OrderedDict(ResourceId=rule['id'],
                                                                        ResourceName=rule['name'],
                                                                        ResourceType='Firewall'))
                        except Exception as e:
                            raise Exception(str(e))
                        if networks.get("nextPageToken"):
                            networks = compute.networks().list(project=project_id,
                                                               pageToken=networks.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_bucket_public_write_prohibited(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            s3_buckets = run_aws_operation(
                credentials, 's3', 'list_buckets')
            operation_args = {}
            grantee_uri = 'http://acs.amazonaws.com/groups/global/AllUsers'
            for bucket in s3_buckets['Buckets']:
                operation_args.update(Bucket=bucket['Name'])
                evaluated_resources += 1
                s3_bucket_acl = run_aws_operation(
                    credentials, 's3', 'get_bucket_acl', operation_args)
                for s3_bucket_acl_grant in s3_bucket_acl['Grants']:
                    if s3_bucket_acl_grant['Permission'] == "WRITE" and \
                            s3_bucket_acl_grant.get('Grantee', {}).get('URI') == grantee_uri:
                        output.append(
                            OrderedDict(
                                ResourceId=bucket['Name'],
                                ResourceName=bucket['Name'],
                                ResourceType='S3'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_changes(self, handler=None):
        output = []
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    cloudwatch_response = run_aws_operation(
                        credentials, 'cloudwatch', 'describe_alarms_for_metric', region_name=region,
                        operation_args=handler)
                    evaluated_resources += 1
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                if not cloudwatch_response['MetricAlarms']:
                    output.append(
                        OrderedDict(
                            ResourceId=self.execution_args['service_account_id'],
                            ResourceName=self.execution_args.get('service_account_name',
                                                                 self.execution_args['service_account_id']),
                            Resource='CloudWatch'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_s3_bucket_policy_changes(self, **kwargs):
        try:
            handler = dict(MetricName='S3BucketEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_cloudtrail_configuration_changes(self, **kwargs):
        try:
            handler = dict(MetricName='CloudTrailEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def audit_alert_configuration_monitoring_security_group_changes(self, **kwargs):
        try:
            handler = dict(MetricName='SecurityGroupEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_rds_instance_public_access_check(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for db in rds_response:
                    evaluated_resources += 1
                    if db['PubliclyAccessible']:
                        for sg in db['VpcSecurityGroups']:
                            operation_args.update(
                                GroupIds=[sg['VpcSecurityGroupId']])
                            security_group = run_aws_operation(
                                credentials, 'ec2', 'describe_security_groups', operation_args, region_name=region)
                            for security_group_ip_permissions in security_group['SecurityGroups']:
                                for sg_info in security_group_ip_permissions['IpPermissions']:
                                    for ip_address in sg_info['IpRanges']:
                                        if ip_address['CidrIp'] == '0.0.0.0/0':
                                            output.append(
                                                OrderedDict(
                                                    ResourceId=db['DBInstanceIdentifier'],
                                                    ResourceName=db['DBInstanceIdentifier'],
                                                    Resource='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_db_instance_backup_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials,
                        'rds',
                        'describe_db_instances',
                        region_name=region,
                        response_key='DBInstances')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for info in rds_response:
                    evaluated_resources += 1
                    if info['BackupRetentionPeriod'] == 0:
                        output.append(
                            OrderedDict(
                                ResourceId=info['DBInstanceIdentifier'],
                                ResourceName=info['DBInstanceIdentifier'],
                                ResourceType='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_guardduty_enabled_centralized(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                evaluated_resources += 1
                try:
                    guard_response = run_aws_operation(
                        credentials,
                        'guardduty',
                        'list_detectors',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                if not guard_response.get('DetectorIds'):
                    output.append(
                        OrderedDict(
                            ResourceId=self.execution_args['service_account_id'],
                            ResourceName=self.execution_args.get('service_account_name',
                                                                 self.execution_args['service_account_id']),
                            ResourceType='Inspector'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_route53_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 1
        try:
            credentials = self.execution_args['auth_values']
            route53_response = run_aws_operation(
                credentials, 'route53', 'list_hosted_zones')
            if not route53_response['HostedZones']:
                output.append(
                    OrderedDict(
                        ResourceId='',
                        ResourceName='',
                        Resource='Route53'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_config_changes(self, **kwargs):
        try:
            handler = dict(MetricName='ConfigEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_route_table_changes(self, **kwargs):
        try:
            handler = dict(MetricName='RouteTableEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_unauthorized_api_call(self, **kwargs):
        try:
            handler = dict(MetricName='AuthorizationFailureCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_management_authentication_failures(self, **kwargs):
        try:
            handler = dict(MetricName='ConsoleSignInFailureCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_iam_policy_changes(self, **kwargs):
        try:
            handler = dict(MetricName='IAMPolicyEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_network_gateways_changes(self, **kwargs):
        try:
            handler = dict(MetricName='NATGateway', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_vpc_changes(self, **kwargs):
        try:
            handler = dict(MetricName='VpcEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_management_console_login_without_mfa(self, **kwargs):
        try:
            handler = dict(MetricName='ConsoleSignInWithoutMfaCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_network_access_control_lists_changes(self, **kwargs):
        try:
            handler = dict(MetricName='NetworkAclEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_root_account_usage(self, **kwargs):
        try:
            handler = dict(MetricName='RootAccountUsageEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_alert_configuration_monitoring_customer_cmks_state_changes(self, **kwargs):
        try:
            handler = dict(MetricName='CMKEventCount', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_aws_organizations_changes_alarm(self, **kwargs):
        try:
            handler = dict(MetricName='OrganizationEvents', Namespace='CloudTrailMetrics')
            output, evaluated_resources = self.aws_audit_alert_configuration_monitoring_changes(handler=handler)
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_use_aws_backup_service_in_use_for_amazon_rds(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    rds_response = run_aws_operation(
                        credentials, 'rds', 'describe_db_instances', region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for info in rds_response['DBInstances']:
                    operation_args = {}
                    operation_args.update(
                        DBInstanceIdentifier=info['DBInstanceIdentifier'])
                    db_snapshot_response = run_aws_operation(
                        credentials, 'rds', 'describe_db_snapshots', operation_args, region_name=region)
                    for snapshot_info in db_snapshot_response['DBSnapshots']:
                        evaluated_resources += 1
                        if snapshot_info['SnapshotType'] != 'awsbackup':
                            output.append(
                                OrderedDict(
                                    ResourceId=snapshot_info['DBSnapshotIdentifier'],
                                    ResourceName=snapshot_info['DBSnapshotIdentifier'],
                                    Resource='RDS'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_audit_organization_in_use(self, **kwargs):
        output = list()
        try:
            service_account_id = self.execution_args.get("service_account_id")
            credentials = self.execution_args['auth_values']
            response = run_aws_operation(
                credentials, 'organizations', 'describe_organization')
            if not response.get('Organization'):
                output.append(
                    OrderedDict(
                        ResourceId='',
                        ResourceName='',
                        ResourceType='Organization'))
        except Exception as e:
            raise Exception(str(e))
        return output, 1

    def aws_vpc_flow_logs_enabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    vpc_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpcs',
                        region_name=region,
                        response_key='Vpcs')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                vpc_ids = [x.get('VpcId', 'NA') for x in vpc_response]
                for vpc_id in vpc_ids:
                    evaluated_resources += 1
                    operation_args = {'Filters': [
                        {
                            'Name': 'resource-id',
                            'Values': [vpc_id]
                        }
                    ]}
                    vpc_flow_log = run_aws_operation(
                        credentials, 'ec2', 'describe_flow_logs', operation_args,
                        region_name=region,
                        response_key='FlowLogs')
                    if not vpc_flow_log:
                        output.append(
                            OrderedDict(
                                ResourceId=vpc_id,
                                ResourceName=vpc_id,
                                ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cmn_audit_ssh_public_keys_rotated_by_days(self, days=30):
        output = list()
        evaluated_resources = 0
        today = datetime.utcnow().replace(tzinfo=None)
        try:
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_users', response_key='Users')
            for iam in iam_response:
                evaluated_resources += 1
                operation_args = dict(UserName=iam.get('UserName', 'NA'))
                iam_ssh_response = run_aws_operation(
                    credentials, 'iam', 'list_ssh_public_keys',
                    operation_args=operation_args,
                    response_key='SSHPublicKeys')
                for user in iam_ssh_response:
                    if (today - user.get('UploadDate', today).replace(tzinfo=None)).days > days:
                        output.append(
                            OrderedDict(
                                ResourceId=iam.get('UserName'),
                                ResourceName=iam.get('UserName'),
                                ResourceType='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cmn_audit_ssl_tls_certificate_expire_by_days(self, expiry_days=30):
        output = list()
        evaluated_resources = 0
        now = datetime.now()
        try:
            credentials = self.execution_args['auth_values']
            certificate_list = run_aws_operation(
                credentials, 'iam', 'list_server_certificates',
                response_key='ServerCertificateMetadataList')
            for certificate_details in certificate_list:
                server_certificate_name = certificate_details.get('ServerCertificateName')
                evaluated_resources += 1
                ssl_expiration_date = certificate_details['Expiration'].replace(
                    tzinfo=None)
                # TODO: make policy dynamic with expiry days as default keys
                if (now - ssl_expiration_date).days > expiry_days:
                    output.append(
                        OrderedDict(
                            ResourceId=server_certificate_name,
                            ResourceName=server_certificate_name,
                            Resource='IAM_Users'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def discovery_check(self, service_account_id):
        try:
            inventory_db = get_mongo_client(self.connection_args)['resource_inventory']
            completed_date = datetime.utcnow() - timedelta(hours=24)
            query_to_check = {"service_account_id": service_account_id, "is_deleted": False,
                              "rediscover_status": "completed", "is_active": True, "data_sync.status": "success",
                              "overall_status": "completed", "data_sync.completed_at": {'$gt': completed_date},
                              "data_sync.message": {'$exists': False}}
            account_info = list()
            account_details = inventory_db["service_inventory_dependency_configuration"].find_one(query_to_check)
            if account_details:
                account_info.append(account_details)
            if len(account_info) != 0:
                return True
            else:
                return False
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_buckets_orphaned(self, **kwargs):
        try:
            output = list()
            service_account_id = self.execution_args["service_account_id"]
            inventory_db = get_mongo_client(self.connection_args)['resource_inventory']
            if self.discovery_check(service_account_id):
                buckets_query = {"service_account_id": service_account_id, "resource_type": "S3", "resource": "Objects",
                                 "category": "Storage", "is_deleted": False}
                buckets_with_obj = inventory_db["service_resource_dependent_inventory"].distinct(
                    "additional_attributes.check_resource_parent_id", buckets_query)
                inventory_query = {"service_account_id": service_account_id, "category": "Storage",
                                   "resource_type": "S3", "resource": "Buckets", "is_deleted": False,
                                   "check_resource_element": {"$nin": buckets_with_obj}}
                violated_resources = list(inventory_db["service_resource_inventory"].find(inventory_query))
                if len(violated_resources) != 0:
                    for resource_details in violated_resources:
                        response = {"ResourceId": resource_details.get("check_resource_element"),
                                    "ResourceName": resource_details.get("summary_details", {}).get("Name", ""),
                                    "ResourceType": resource_details.get("resource_type", ""),
                                    "Resource": resource_details.get("resource", ""),
                                    "Region": resource_details.get("summary_details", {}).get("location", "")}
                        output.append(response)
            return output, len(output)
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_objects_duplicate(self, **kwargs):
        try:
            output = list()
            service_account_id = self.execution_args["service_account_id"]
            inventory_db = get_mongo_client(self.connection_args)['resource_inventory']
            if self.discovery_check(service_account_id):
                output = list(inventory_db["service_resource_dependent_inventory"].aggregate([{"$match":
                    {
                        "service_account_id": service_account_id, 'is_deleted': False
                        , 'summary_details.IsLatest': True
                    }},
                    {"$group": {"_id": {
                        "ResourceId": {'$arrayElemAt': [{'$split': ["$check_resource_element", '/']}, -1]},
                        "bucketName": "$additional_attributes.check_resource_parent_id",
                        "Size": "$summary_details.Size"
                    },
                        "count": {
                            "$sum": 1}}},
                    {"$match": {
                        "_id": {"$ne": None},
                        "count": {"$gt": 1}}},
                    {"$addFields": {
                        "ResourceType": "S3",
                        "Resource": "Objects"}},
                    {"$project": {"_id": 0,
                                  "ResourceType": "$ResourceType",
                                  "Resource": "$Resource",
                                  "ResourceId": "$_id.ResourceId",
                                  "bucketName": "$_id.bucketName",
                                  "Size": "$_id.Size",
                                  "Count": "$count"
                                  }}], allowDiskUse=True))
            return output, len(output)
        except Exception as e:
            raise Exception(str(e))

    def aws_s3_objects_aged(self, **kwargs):
        try:
            output = list()
            service_account_id = self.execution_args["service_account_id"]
            elapsed_days = self.execution_args['args'].get("ElapsedDays")
            inventory_db = get_mongo_client(self.connection_args)['resource_inventory']
            if self.discovery_check(service_account_id):
                inventory_query = {"service_account_id": service_account_id, "category": "Storage",
                                   "resource_type": "S3", "resource": "Objects", "is_deleted": False}
                objects_in_inventory = list(inventory_db["service_resource_dependent_inventory"].find(inventory_query))
                if len(objects_in_inventory) != 0:
                    for objects in objects_in_inventory:
                        last_modified = parse(objects.get("summary_details").get("LastModified"))
                        days_to_check = datetime.now(timezone.utc) - last_modified
                        if days_to_check.days > int(elapsed_days):
                            response = {"ResourceId": objects.get("check_resource_element"),
                                        "BucketName": objects.get("summary_details").get("bucketName"),
                                        "ResourceType": objects.get("resource_type", ""),
                                        "Region": objects.get("location", ""),
                                        "Resource": objects.get("resource", ""),
                                        "Size": objects.get("summary_details").get("Size"),
                                        "LastModified": last_modified.isoformat()}
                            output.append(response)
            return output, len(output)
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_basic_user_role(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('cloudresourcemanager', 'v1',
                                                 credentials=credential) as cloudresourcemanager:
                try:
                    request = cloudresourcemanager.projects().getIamPolicy(resource=project_id).execute()
                    while True:
                        for members in request.get('bindings', []):
                            evaluated_resources += 1
                            if members.get("role", "") in ["roles/owner", "roles/writer", "roles/reader"]:
                                for user in members.get("members", []):
                                    user_name = user.split(":")
                                    if user_name[0] == "user":
                                        output.append(
                                            OrderedDict(ResourceId=user_name[1],
                                                        ResourceName=user_name[1],
                                                        ResourceType='Roles'))
                        if request.get("nextPageToken"):
                            request = cloudresourcemanager.projects().getIamPolicy(resource=project_id,
                                                                                   pageToken=request.get(
                                                                                       "nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_dns_logging_diabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('dns', 'v1beta2', credentials=credential) as dns:
                try:
                    request = dns.policies().list(project=project_id).execute()
                    while True:
                        for dns_name in request.get("policies", []):
                            evaluated_resources += 1
                            if not dns_name.get("enableLogging"):
                                output.append(
                                    OrderedDict(ResourceId=dns_name.get("id", "NA"),
                                                ResourceName=dns_name.get("name", "NA"),
                                                ResourceType='Manged_Zones'))
                        if request.get("nextPageToken"):
                            request = dns.policies().list(project=project_id,
                                                          pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_firewall_rule_logging(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                try:
                    request = compute.firewalls().list(project=project_id).execute()
                    while True:
                        for firewall_rules in request.get("items", []):
                            evaluated_resources += 1
                            if not firewall_rules["logConfig"].get("enable", False) and not firewall_rules.get(
                                    "disabled", False):
                                output.append(
                                    OrderedDict(ResourceId=firewall_rules.get("id", "NA"),
                                                ResourceName=firewall_rules.get("name", "NA"),
                                                ResourceType='Firewall'))
                        if request.get("nextPageToken"):
                            request = compute.policies().list(project=project_id,
                                                              pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_confidential_computing_disabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                try:
                    for zone in zones:
                        request = compute.instances().list(project=project_id, zone=zone).execute()
                        if request.get("items"):
                            for instance in request["items"]:
                                evaluated_resources += 1
                                if not instance.get("confidentialInstanceConfig", {}).get("enableConfidentialCompute"):
                                    output.append(
                                        OrderedDict(ResourceId=instance.get("id", "NA"),
                                                    ResourceName=instance.get("name", "NA"),
                                                    ResourceType='VM_Instances'))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_deafult_service_account_used(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            with googleapiclient.discovery.build('iam', 'v1', credentials=credential) as iam:
                try:
                    project_id_format = "projects/" + project_id
                    request = iam.projects().serviceAccounts().list(name=project_id_format).execute()
                    for service_account in request.get("accounts", []):
                        if service_account.get("displayName") == "Compute Engine default service account":
                            default_account_email = service_account.get("email")
                            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                                try:
                                    for zone in zones:
                                        request = compute.instances().list(project=project_id, zone=zone).execute()
                                        for vm_machine in request.get("items", []):
                                            evaluated_resources += 1
                                            for accounts in vm_machine.get("serviceAccounts"):
                                                if accounts.get("email") == default_account_email:
                                                    output.append(
                                                        OrderedDict(ResourceId=vm_machine.get("id", "NA"),
                                                                    ResourceName=vm_machine.get("name", "NA"),
                                                                    ResourceType='VM_Instances'))
                                except Exception as e:
                                    raise Exception(str(e))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sheilded_vm_disabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                try:
                    for zone in zones:
                        request = compute.instances().list(project=project_id, zone=zone).execute()
                        if request.get("items"):
                            for instance in request["items"]:
                                evaluated_resources += 1
                                if not instance.get("shieldedInstanceConfig"):
                                    output.append(
                                        OrderedDict(ResourceId=instance.get("id", "NA"),
                                                    ResourceName=instance.get("name", "NA"),
                                                    ResourceType='VM_Instances'))
                                elif not instance.get("shieldedInstanceConfig").get(
                                        "enableSecureBoot") or not instance.get("shieldedInstanceConfig").get(
                                    "enableVtpm") or not instance.get("shieldedInstanceConfig").get(
                                    "enableIntegrityMonitoring"):
                                    output.append(
                                        OrderedDict(ResourceId=instance.get("id", "NA"),
                                                    ResourceName=instance.get("name", "NA"),
                                                    ResourceType='VM_Instances'))
                            if request.get("nextPageToken"):
                                request = compute.instances().list(project=project_id, zone=zone,
                                                                   pageToken=request.get("nextPageToken")).execute()
                            else:
                                break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_dataset_cmek_disabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('bigquery', 'v2', credentials=credential) as bigquery:
                try:
                    request = bigquery.datasets().list(projectId=project_id).execute()
                    while True:
                        for dataset in request.get("datasets", []):
                            evaluated_resources += 1
                            if not dataset.get("defaultEncryptionConfiguration"):
                                output.append(
                                    OrderedDict(ResourceId=dataset.get("id", "NA"),
                                                ResourceName=dataset.get("name", "NA"),
                                                ResourceType='Datasets'))
                            elif not dataset["defaultEncryptionConfiguration"].get("kmsKeyName"):
                                output.append(
                                    OrderedDict(ResourceId=dataset.get("id", "NA"),
                                                ResourceName=dataset.get("name", "NA"),
                                                ResourceType='Datasets'))
                        if request.get("nextPageToken"):
                            request = bigquery.datasets().list(projectId=project_id,
                                                               pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_storage_bucket_cmek_disabled(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('storage', 'v1', credentials=credential) as storage:
                try:
                    request = storage.buckets().list(project=project_id).execute()
                    while True:
                        for bucket in request.get("items", []):
                            evaluated_resources += 1
                            if not bucket.get("encryption") or not bucket.get('encryption').get('defaultKmsKeyName'):
                                output.append(
                                    OrderedDict(ResourceId=bucket.get("id", "NA"),
                                                ResourceName=bucket.get("name", "NA"),
                                                ResourceType='Buckets'))
                        if request.get("nextPageToken"):
                            request = storage.buckets().list(project=project_id,
                                                             pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_unrestricted_outbound_access(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                try:
                    networks = compute.networks().list(project=project_id).execute()
                    self_link_list = list()
                    while True:
                        for network in networks.get('items', []):
                            self_link_list.append(network.get("selfLink"))
                        try:
                            firewall_rules_list = compute.firewalls().list(project=project_id).execute()
                            for network_self_link in self_link_list:
                                flag = False
                                evaluated_resources += 1
                                firewall_rules = [rules for rules in firewall_rules_list.get("items", []) if
                                                  rules.get("network") == network_self_link]
                                for rule in firewall_rules:
                                    if not rule.get("disabled") and rule.get("direction") == "EGRESS" and rule.get(
                                            "denied") and rule.get("destinationRanges")[0] == "0.0.0.0/0":
                                        if rule["denied"][0].get("IPProtocol") == "all":
                                            flag = True
                                if not flag:
                                    output.append(
                                        OrderedDict(ResourceId=network_self_link.split("/networks/")[1],
                                                    ResourceName=network_self_link.split("/networks/")[1],
                                                    ResourceType='Network'))
                        except Exception as e:
                            raise Exception(str(e))
                        if networks.get("nextPageToken"):
                            networks = compute.networks().list(project=project_id,
                                                               pageToken=networks.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_min_error_statement_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'P' or 'p':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "log_min_error_statement" and not flags.get(
                                                "value") == value:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_sqlserver_contained_database_authentication_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'S' or 's':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "contained database authentication" and flags.get(
                                                "value") in ["ON", "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_sqlserver_cross_db_ownership_chaining_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'S' or 's':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "cross db ownership chaining" and flags.get(
                                                "value") in ["ON", "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_sqlserver_external_scripts_enabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'S' or 's':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "external scripts enabled" and flags.get("value") in [
                                            "ON", "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_sqlinstance_local_infile_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'M' or 'm':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "local_infile" and flags.get("value") in ["ON", "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_min_duration_statement_enabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'P' or 'p':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "log_min_duration_statement" and flags.get(
                                                "value") != "-1":
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_parser_stats_enabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'P' or 'p':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "log_parser_stats" and flags.get("value") in ["ON",
                                                                                                              "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_planner_stats_enabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'P' or 'p':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "log_planner_stats" and flags.get("value") in ["ON",
                                                                                                               "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_statement_stats_enabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'P' or 'p':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "log_statement_stats" and flags.get("value") in ["ON",
                                                                                                                 "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_sqlserver_remote_access_enabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'S' or 's':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "remote access" and flags.get("value") in ["ON", "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_checkpoints_disabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            value = self.execution_args.get('args', {}).get("flag_value")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                try:
                    request = sql.instances().list(project=project_id).execute()
                    while True:
                        for instance in request.get("items", []):
                            if instance.get("databaseVersion").split()[0] == 'P' or 'p':
                                evaluated_resources += 1
                                if instance.get("settings").get("databaseFlags"):
                                    for flags in instance["settings"]["databaseFlags"]:
                                        if flags.get("name") == "log_checkpoints" and not flags.get("value") in ["ON",
                                                                                                                 "on"]:
                                            output.append(
                                                OrderedDict(ResourceId=instance.get("id", "NA"),
                                                            ResourceName=instance.get("name", "NA"),
                                                            ResourceType='SQL_Instances_Databases'))
                        if request.get("nextPageToken"):
                            request = sql.instances().list(project=project_id,
                                                           pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
                except Exception as e:
                    raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_cloudtrail_log_file_validation_enabled(self, **kwargs):
        output = list()
        try:
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                credentials = self.execution_args['auth_values']
                trail_response = run_aws_operation(
                    credentials, 'cloudtrail', 'describe_trails', region_name=region)

                try:
                    for trait in trail_response.get('trailList', []):
                        if not trait.get('LogFileValidationEnabled'):
                            output.append(
                                OrderedDict(
                                    ResourceId=trait.get('Name', self.execution_args['service_account_id']),
                                    ResourceName=trait.get('TrailARN', self.execution_args['service_account_name']),
                                    ResourceType='CloudTrail'))

                except Exception as e:
                    raise Exception(str(e))
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def aws_cloud_trail_encryption(self, **kwargs):
        output = list()
        try:
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                credentials = self.execution_args['auth_values']
                trail_response = run_aws_operation(
                    credentials, 'cloudtrail', 'describe_trails', region_name=region)

                try:
                    for trait in trail_response.get('trailList', []):
                        if not trait.get('KmsKeyId'):
                            output.append(
                                OrderedDict(
                                    ResourceId=trait.get('Name', self.execution_args['service_account_id']),
                                    ResourceName=trait.get('TrailARN', self.execution_args['service_account_name']),
                                    ResourceType='CloudTrail'))

                except Exception as e:
                    raise Exception(str(e))
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def aws_multi_region_cloudtrail_enabled(self, **kwargs):
        output = list()
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                trail_response = run_aws_operation(
                    credentials, 'cloudtrail', 'describe_trails', region_name=region)

                try:
                    for trait in trail_response.get('trailList', []):
                        if not trait.get('IsMultiRegionTrail'):
                            output.append(
                                OrderedDict(
                                    ResourceId=trait.get('Name', self.execution_args['service_account_id']),
                                    ResourceName=trait.get('TrailARN', self.execution_args['service_account_name']),
                                    ResourceType='CloudTrail'))

                except Exception as e:
                    raise Exception(str(e))
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def aws_cloudwatch_log_group_encrypted(self, **kwargs):
        output = list()
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                log_group_response = run_aws_operation(
                    credentials, 'logs', 'describe_log_groups', region_name=region)

                try:
                    for log_group in log_group_response:
                        if log_group and isinstance(log_group, dict):
                            if not log_group.get('kmsKeyId'):
                                output.append(
                                    OrderedDict(
                                        ResourceId=log_group.get('logGroupName', ''),
                                        ResourceName=log_group.get('logGroupName', ''),
                                        ResourceType='CloudTrail'))

                except Exception as e:
                    raise Exception(str(e))
            return output, 1
        except Exception as e:
            raise Exception(str(e))

    def check_gcp_vm_instance_disk_not_encrypted_with_cmek(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            zones = [zone.get('name') for zone in self.execution_args['zones']]
            with googleapiclient.discovery.build('compute', 'v1', credentials=credential) as compute:
                for zone in zones:
                    request = compute.instances().list(project=project_id, zone=zone).execute()
                    if request.get("items"):
                        for instance in request["items"]:
                            if instance.get("disks"):
                                for disks in instance["disks"]:
                                    evaluated_resources += 1
                                    if disks.get("diskEncryptionKey"):
                                        if not disks["diskEncryptionKey"].get("kmsKeyName"):
                                            output.append(
                                                OrderedDict(ResourceId=disks.get("deviceName", "NA"),
                                                            ResourceName=disks.get("deviceName", "NA"),
                                                            ResourceType='Disks'))
                                    else:
                                        output.append(
                                            OrderedDict(ResourceId=disks.get("deviceName", "NA"),
                                                        ResourceName=disks.get("deviceName", "NA"),
                                                        ResourceType='Disks'))
                        if request.get("nextPageToken"):
                            request = compute.instances().list(project=project_id, zone=zone,
                                                               pageToken=request.get("nextPageToken")).execute()
                        else:
                            break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_gcp_sql_instance_using_public_ip(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sqladmin:
                request = sqladmin.instances().list(project=project_id).execute()
                while request.get("items"):
                    instance_list = []
                    for sql_instance in request["items"]:
                        evaluated_resources += 1
                        if sql_instance.get("ipAddresses"):
                            for ip_address in sql_instance["ipAddresses"]:
                                if ip_address["type"] == "PRIMARY" and not sql_instance.get(
                                        "name") in instance_list:
                                    instance_list.append(sql_instance.get("name"))
                                    output.append(
                                        OrderedDict(ResourceId=sql_instance.get("name", "NA"),
                                                    ResourceName=sql_instance.get("name", "NA"),
                                                    ResourceType='SQL_Instances'))
                    if request.get("nextPageToken"):
                        request = sqladmin.instances().list(project=project_id,
                                                            pageToken=request.get("nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_gcp_over_privileged_service_account_user(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('cloudresourcemanager', 'v1',
                                                 credentials=credential) as cloudresourcemanager:
                request = cloudresourcemanager.projects().getIamPolicy(resource=project_id).execute()
                members_list = []
                for principal in request.get("bindings", []):
                    evaluated_resources += 1
                    if principal.get("role") in ["roles/iam.serviceAccountTokenCreator",
                                                 "roles/iam.serviceAccountUser"]:
                        for members in principal["members"]:
                            if members[0:4] == "user" and members[5:] not in members_list:
                                members_list.append(members[5:])
                                output.append(
                                    OrderedDict(ResourceId=members[5:],
                                                ResourceName=members[5:],
                                                ResourceType='Roles'))
                        if request.get("nextPageToken"):
                            request = cloudresourcemanager.projects().getIamPolicy(resource=project_id,
                                                                                   pageToken=request.get(
                                                                                       "nextPageToken")).execute()
                        else:
                            break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def check_gcp_service_account_key_not_rotated(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('iam', 'v1', credentials=credential) as iam:
                while True:
                    format_project_id = "projects/" + project_id
                    request = iam.projects().serviceAccounts().list(name=format_project_id).execute()
                    for account in request.get("accounts", []):
                        evaluated_resources += 1
                        format_service_account = format_project_id + "/serviceAccounts/" + account.get("email")
                        request_keys = iam.projects().serviceAccounts().keys().list(
                            name=format_service_account).execute()
                        if request_keys.get("keys"):
                            for keys in request_keys["keys"]:
                                time_str = keys["validAfterTime"]
                                time_formated = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")
                                forcasted_date = datetime.now() - timedelta(days=90)
                                if forcasted_date > time_formated:
                                    output.append(
                                        OrderedDict(ResourceId=keys["name"].split("/keys/")[1],
                                                    ResourceName=account["email"],
                                                    ResourceType='Roles'))
                    if request_keys.get("nextPageToken"):
                        request_keys = iam.projects().serviceAccounts().list(name=format_project_id,
                                                                             pageToken=request.get(
                                                                                 "nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_connections_disabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                request = sql.instances().list(project=project_id).execute()
                while True:
                    for instance in request.get("items", []):
                        if instance.get("databaseVersion")[0].lower() == 'p':
                            evaluated_resources += 1
                            if instance.get("settings").get("databaseFlags"):
                                for flags in instance["settings"]["databaseFlags"]:
                                    if flags.get("name") == "log_connections" and flags.get(
                                            "value") not in ["ON", "on"]:
                                        output.append(
                                            OrderedDict(ResourceId=instance.get("id", "NA"),
                                                        ResourceName=instance.get("name", "NA"),
                                                        ResourceType='SQL_Instances_Databases'))
                    if request.get("nextPageToken"):
                        request = sql.instances().list(project=project_id,
                                                       pageToken=request.get("nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_disconnections_disabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                request = sql.instances().list(project=project_id).execute()
                while True:
                    for instance in request.get("items", []):
                        if instance.get("databaseVersion")[0].lower() == 'p':
                            evaluated_resources += 1
                            if instance.get("settings").get("databaseFlags"):
                                for flags in instance["settings"]["databaseFlags"]:
                                    if flags.get("name") == "log_disconnections" and flags.get(
                                            "value") not in ["ON", "on"]:
                                        output.append(
                                            OrderedDict(ResourceId=instance.get("id", "NA"),
                                                        ResourceName=instance.get("name", "NA"),
                                                        ResourceType='SQL_Instances_Databases'))
                    if request.get("nextPageToken"):
                        request = sql.instances().list(project=project_id,
                                                       pageToken=request.get("nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_hostname_enabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                request = sql.instances().list(project=project_id).execute()
                while True:
                    for instance in request.get("items", []):
                        if instance.get("databaseVersion")[0].lower() == 'p':
                            evaluated_resources += 1
                            if instance.get("settings").get("databaseFlags"):
                                for flags in instance["settings"]["databaseFlags"]:
                                    if flags.get("name") == "log_hostname" and flags.get(
                                            "value") in ["ON", "on"]:
                                        output.append(
                                            OrderedDict(ResourceId=instance.get("id", "NA"),
                                                        ResourceName=instance.get("name", "NA"),
                                                        ResourceType='SQL_Instances_Databases'))
                    if request.get("nextPageToken"):
                        request = sql.instances().list(project=project_id,
                                                       pageToken=request.get("nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_locks_waits_disabled_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                request = sql.instances().list(project=project_id).execute()
                while True:
                    for instance in request.get("items", []):
                        if instance.get("databaseVersion")[0].lower() == 'p':
                            evaluated_resources += 1
                            if instance.get("settings").get("databaseFlags"):
                                for flags in instance["settings"]["databaseFlags"]:
                                    if flags.get("name") == "log_lock_waits" and flags.get(
                                            "value") not in ["ON", "on"]:
                                        output.append(
                                            OrderedDict(ResourceId=instance.get("id", "NA"),
                                                        ResourceName=instance.get("name", "NA"),
                                                        ResourceType='SQL_Instances_Databases'))
                    if request.get("nextPageToken"):
                        request = sql.instances().list(project=project_id,
                                                       pageToken=request.get("nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_postgresql_log_temp_files_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                request = sql.instances().list(project=project_id).execute()
                while True:
                    for instance in request.get("items", []):
                        if instance.get("databaseVersion")[0].lower() == 'p':
                            evaluated_resources += 1
                            if instance.get("settings").get("databaseFlags"):
                                for flags in instance["settings"]["databaseFlags"]:
                                    if flags.get("name") == "log_temp_files" and flags.get(
                                            "value") != "0":
                                        output.append(
                                            OrderedDict(ResourceId=instance.get("id", "NA"),
                                                        ResourceName=instance.get("name", "NA"),
                                                        ResourceType='SQL_Instances_Databases'))
                    if request.get("nextPageToken"):
                        request = sql.instances().list(project=project_id,
                                                       pageToken=request.get("nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def gcp_audit_sql_sqlinstance_skip_show_database_flag(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            credential = get_credential(credentials)
            project_id = credentials.get("project_id")
            with googleapiclient.discovery.build('sqladmin', 'v1beta4', credentials=credential) as sql:
                request = sql.instances().list(project=project_id).execute()
                while True:
                    for instance in request.get("items", []):
                        if instance.get("databaseVersion")[0].lower() == 'm':
                            evaluated_resources += 1
                            if instance.get("settings").get("databaseFlags"):
                                for flags in instance["settings"]["databaseFlags"]:
                                    if flags.get("name") == "skip_show_database" and \
                                            flags.get("value") not in ["ON", "on"]:
                                        output.append(
                                            OrderedDict(ResourceId=instance.get("id", "NA"),
                                                        ResourceName=instance.get("name", "NA"),
                                                        ResourceType='SQL_Instances_Databases'))
                    if request.get("nextPageToken"):
                        request = sql.instances().list(project=project_id,
                                                       pageToken=request.get("nextPageToken")).execute()
                    else:
                        break
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def common_kms_customer_master_key_in_use(self, input_key, input_value):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            tag_key = input_key
            tag_value = input_value
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_response = run_aws_operation(
                        credentials,
                        'kms',
                        'list_keys',
                        region_name=region,
                        response_key='Keys')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for keys in kms_response:
                    operation_args.update(KeyId=keys['KeyId'])
                    evaluated_resources += 1
                    try:
                        key_response = run_aws_operation(
                            credentials,
                            'kms',
                            'list_resource_tags',
                            region_name=region,
                            operation_args=operation_args)
                        if not key_response['Tags']:
                            output.append(
                                OrderedDict(
                                    ResourceId=keys['KeyId'],
                                    ResourceName=keys['KeyId'],
                                    ResourceType='kms'))
                        else:
                            for tag in key_response['Tags']:
                                if tag['Key'] != tag_key and tag['Value'] != tag_value:
                                    output.append(
                                        OrderedDict(
                                            ResourceId=keys['KeyId'],
                                            ResourceName=keys['KeyId'],
                                            ResourceType='kms'))
                    except Exception as e:
                        raise Exception(str(e))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_web_tier_kms_customer_master_key_in_use(self):
        web_tier_tag_key = self.execution_args["args"]["web_tier_tag_key"]
        web_tier_tag_value = self.execution_args["args"]["web_tier_tag_value"]
        output, evaluated_resources = self.common_kms_customer_master_key_in_use(web_tier_tag_key, web_tier_tag_value)
        return output, evaluated_resources

    def aws_iam_trusted_entities_without_mfa(self, **kwargs):
        output = list()
        evaluated_resources = 0
        compliant_federated_values = ['ge-saml-for-aws-mfa', 'ge-saml-for-aws-mfa-extended']
        non_compliant_federated_values = 'ge-saml-for-aws'
        not_applicable_annotation = 'NOT_APPLICABLE: Non GE Saml are not applicable'
        try:
            credentials = self.execution_args['auth_values']
            iam_response = run_aws_operation(
                credentials, 'iam', 'list_roles')
            for roles in iam_response['Roles']:
                evaluated_resources += 1
                for statement in roles['AssumeRolePolicyDocument']['Statement']:
                    federated_value = statement.get('Principal', {}).get('Federated', {})
                    if statement['Effect'] == 'Allow' and federated_value:
                        is_federated_role = True
                    if isinstance(federated_value, str):
                        if any([federated_value.endswith(cfv) for cfv in compliant_federated_values]):
                            compliant_federation = True
                        elif federated_value.endswith(non_compliant_federated_values):
                            noncompliant_federation = True
                        else:
                            not_applicable_federated = True
                    else:
                        compliance_flags = []
                        for federated_value_item in federated_value:
                            if any([federated_value_item.endswith(cfv) for cfv in compliant_federated_values]):
                                compliance_flags.append(True)
                            elif federated_value_item.endswith(non_compliant_federated_values):
                                compliance_flags.append(False)
                        if len(compliance_flags) == 0:
                            not_applicable_federated = True
                        elif all(compliance_flags):
                            compliant_federation = True
                        else:
                            noncompliant_federation = True
                if not is_federated_role:
                    continue
                if not_applicable_federated == True:
                    print(not_applicable_annotation)
                elif compliant_federation == True and noncompliant_federation == False:
                    continue
                else:
                    output.append(
                        OrderedDict(
                            ResourceId=roles['RoleName'],
                            ResourceName=roles['RoleName'],
                            ResourceType='IAM_Roles'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_vpc_endpoints_encryption(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    vpc_endpoints = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_vpc_endpoints',
                        region_name=region,
                        response_key='VpcEndpoints')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
            for vpc_endpoint in vpc_endpoints:
                evaluated_resources += 1
                vpc_endpoint_has_secure_transport = False
                vpc_endpoint_policy_document = json.loads(vpc_endpoint['PolicyDocument'])['Statement']
                for attribute in vpc_endpoint_policy_document:
                    if self.has_secure_transport(attribute):
                        vpc_endpoint_has_secure_transport = True
                if not vpc_endpoint_has_secure_transport:
                    output.append(
                        OrderedDict(
                            ResourceId=vpc_endpoint['VpcEndpointId'],
                            ResourceName=vpc_endpoint['VpcEndpointId'],
                            Resource='VPC'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_lambda_with_secure_environment_variables(self, **kwargs):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        not_allowed_patterns = r'(?:key|secret|pass|pw|credential|token)(?!.*?(?:id|context|endpoint|url))'
        credentials = self.execution_args['auth_values']
        try:
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    lambda_response = run_aws_operation(
                        credentials,
                        'lambda',
                        'list_functions',
                        region_name=region,
                        response_key='Functions')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for function in lambda_response:
                    evaluated_resources += 1
                    operation_args = {}
                    operation_args.update(
                        FunctionName=function['FunctionName'])
                    try:
                        versions = run_aws_operation(
                            credentials,
                            'lambda',
                            'list_versions_by_function',
                            region_name=region,
                            operation_args=operation_args)
                        versions = sorted(versions, key=lambda v: len(versions) if v['Version'] == '$LATEST' else int(
                            v['Version']), reverse=True)
                        for version in versions:
                            version_evaluation = None
                        # If not encrypted by customer managed CMK, compliant
                        if 'KMSKeyArn' not in version:
                            output.append(
                                OrderedDict(
                                    ResourceId=function['FunctionName'],
                                    ResourceName=function['FunctionName'],
                                    ResourceType='lambda'))
                            # If there are no environment variables, not applicable
                        elif ('Environment' not in version) or ('Variables' not in version['Environment']):
                            continue
                        # Otherwise, testing the variables individually
                        else:
                            sensitive_variables = []
                            insecure_variables = []
                        for name, value in version['Environment']['Variables'].items():
                            if re.search(not_allowed_patterns, name.lower()):
                                sensitive_variables.append(name)
                                # If empty, compliant
                                if len(value) == 0:
                                    pass
                                # If too short to be a ciphertext, non-compliant
                                # NOTE: this is a guess, seems to work fine so far
                                elif len(value) < 64:
                                    insecure_variables.append(name)
                                else:
                                    try:
                                        # Ciphertexts are Base64 encoded, should be able to decode
                                        decoded = base64.b64decode(value)
                                        try:
                                            # Looks like a ciphertext, validating with KMS
                                            # The ciphertext format is not published, but KMS throws an error if invalid
                                            operation_args.update(CiphertextBlob=decoded)
                                            kms_client = run_aws_operation(
                                                credentials,
                                                'kms',
                                                'decrypt',
                                                region_name=region,
                                                operation_args=operation_args)
                                            # If KMS could decrypt it, it was a ciphertext, so compliant
                                            pass
                                        except ClientError as e:
                                            # If KMS thinks it is not a ciphertext, non-compliant
                                            if e.response['Error']['Code'] == 'InvalidCiphertextException':
                                                insecure_variables.append(name)
                                        except:
                                            # If KMS throw any other error (e.g., access denied), it was likely a ciphertext, so compliant
                                            pass
                                    except:
                                        # If not in Base64, not a ciphertext, so non-compliant
                                        insecure_variables.append(name)
                        if len(insecure_variables) != 0:
                            output.append(
                                OrderedDict(
                                    ResourceId=function['FunctionName'],
                                    ResourceName=function['FunctionName'],
                                    ResourceType='lambda'))
                    except Exception as e:
                        if "ResourceNotFoundError" in str(e):
                            continue
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

    def aws_vpc_nacl_alignment(self, **kwargs):
        output = list()
        evaluated_resources = 0
        security_group_ports = []
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    network_response = run_aws_operation(
                        credentials, 'ec2', 'describe_network_acls',
                        region_name=region,
                        response_key='NetworkAcls')
                    security_groups_response = run_aws_operation(
                        credentials, 'ec2', 'describe_security_groups',
                        region_name=region,
                        response_key='SecurityGroups')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                for security_group in security_groups_response:
                    for permission in security_group['IpPermissions']:
                        try:
                            if not permission.get('FromPort'):
                                output.append(
                                    OrderedDict(
                                        ResourceId=security_group['GroupId'],
                                        ResourceName=security_group['GroupId'],
                                        Resource='EC2'))
                            if permission['FromPort'] not in security_group_ports:
                                security_group_ports.append(permission['FromPort'])
                        except Exception as e:
                            if 'FromPort' in str(e):
                                output.append(
                                    OrderedDict(
                                        ResourceId=security_group['GroupId'],
                                        ResourceName=security_group['GroupId'],
                                        Resource='EC2'))
                        for ip in permission['IpRanges']:
                            if ip['CidrIp'] == '0.0.0.0/0':
                                output.append(
                                    OrderedDict(
                                        ResourceId=security_group['GroupId'],
                                        ResourceName=security_group['GroupId'],
                                        Resource='EC2'))
                for network_acl in network_response:
                    evaluated_resources += 1
                    for entry in network_acl['Entries']:
                        port_range = entry.get('PortRange')
                        if entry.get('Egress') == True:
                            continue
                        if entry.get('RuleAction') == 'deny':
                            continue
                        if entry['CidrBlock'] == '0.0.0.0/0':
                            output.append(
                                OrderedDict(
                                    ResourceId=network_acl['NetworkAclId'],
                                    ResourceName=network_acl['NetworkAclId'],
                                    Resource='EC2'))
                        if port_range:
                            if not port_range.get('From'):
                                output.append(
                                    OrderedDict(
                                        ResourceId=network_acl['NetworkAclId'],
                                        ResourceName=network_acl['NetworkAclId'],
                                        Resource='NACL'))
                            if port_range['From'] not in security_group_ports:
                                output.append(
                                    OrderedDict(
                                        ResourceId=network_acl['NetworkAclId'],
                                        ResourceName=network_acl['NetworkAclId'],
                                        Resource='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))


    def aws_ec2_instance_with_https_redirect(self):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id')
                       for region in self.execution_args['regions']]
            for region in regions:
                try:
                    instance_dict = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_instances',
                        region_name=region).get('Reservations')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))
                operation_args = {}
                for reservation in instance_dict:
                    for instance in reservation.get('Instances'):
                        evaluated_resources += 1
                        for sg in instance.get('SecurityGroups'):
                            operation_args.update(GroupIds=[sg.get('GroupId')])
                            security_groups = run_aws_operation(
                                credentials,
                                'ec2',
                                'describe_security_groups',
                                operation_args,
                                region_name=region)
                            for security_group in security_groups.get(
                                    'SecurityGroups'):
                                security_group_compliant = True
                                for security_group_ippermissions in security_group['IpPermissions']:
                                    if (security_group_ippermissions['IpProtocol']) != '-1':
                                        if (security_group_ippermissions['FromPort'] != 443 and
                                                security_group_ippermissions['ToPort'] != 443):
                                            security_group_compliant = False
                            if not security_group_compliant:
                                output.append(
                                    OrderedDict(
                                        ResourceId=instance['InstanceId'],
                                        ResourceName=instance['InstanceId'],
                                        ResourceType='EC2'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))