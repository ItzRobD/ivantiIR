import asyncio
import pandas as pd
from dataclasses import dataclass
from datetime import datetime, timedelta

from azure.identity.aio import ClientSecretCredential
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph import GraphServiceClient
from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import SignInsRequestBuilder


# https://devblogs.microsoft.com/microsoft365dev/introducing-the-microsoft-graph-python-sdk/
# https://learn.microsoft.com/en-us/graph/api/riskdetection-list?view=graph-rest-1.0&tabs=python
# https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0&tabs=python
# https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0&tabs=python


# I used dataclasses in order to handle the required data in a more structured format
@dataclass
class User:
    id: str
    display_name: str
    risk_level: str
    risk_state: str
    risk_detail: str
    is_deleted: bool

@dataclass
class Detection:
    id: str
    created_date_time: datetime
    activity: str
    user_id: str
    user_display_name:str
    detection_timing: str
    risk_level: str
    risk_event_type: str
    risk_detail: str

@dataclass
class AuditLog:
    id: str
    user_id: str
    user_display_name: str
    created_date_time: datetime
    ipAddress: str
    clientApp: str
    city: str
    state: str
    country: str

class RiskyLogCollector:
    def __init__(self, user_input):
        self.name = "Azure"
        self.credentials = ClientSecretCredential(
            user_input['tenant_id'],
            user_input['client_id'],
            user_input['client_secret'],
        )
        self.scopes = ['https://graph.microsoft.com/.default']
        self.client = GraphServiceClient(credentials=self.credentials, scopes=self.scopes)
        self.risky_users = []

    async def get_risk_detections(self) -> list:
        """
        Gets a list of risk detections and translates them into a structured format for later use
        :return: list of risk detections
        :rtype: list
        """
        result = await self.client.identity_protection.risk_detections.get()
        # this request returns a RiskDetectionCollectionResponse
        # value is a list of detections
        risk_detections = []
        if result.value:
            for detection in result.value:
                d = Detection(
                    id=detection.id,
                    created_date_time=detection.activity_date_time,
                    activity=detection.activity,
                    user_id=detection.user_id,
                    user_display_name=detection.user_display_name,
                    detection_timing=detection.detection_timing_type,
                    risk_level=detection.risk_level,
                    risk_event_type=detection.risk_event_type,
                    risk_detail=detection.risk_detail,
                )
                risk_detections.append(d)
            return risk_detections

    async def entra_get_last_30d_sign_ins_for_userid(self, target_user_id) -> list:
        """
        Gets the last 30 days of sign ins for a specific user from entra
        :param target_user_id: user id to query
        :return: list of specified user's audit logs
        :rtype: list
        """
        start_date = datetime.now() - timedelta(days=30)
        now = datetime.now()
        filter = (f'createdDateTime ge {datetime.isoformat(start_date)} and createdDateTime le {datetime.isoformat(now)}'
                  f' userId eq {target_user_id}')
        query_params = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
            filter=filter,
        )
        request_configuration = RequestConfiguration(
            query_parameters=query_params
        )
        log_list = []
        result = await self.client.audit_logs.sign_ins.get(request_configuration=request_configuration)
        if result.value:
            for log in result.value:
                al = AuditLog(
                    id=log.id,
                    user_id=log.user_id,
                    user_display_name=log.user_display_name,
                    created_date_time=log.created_date_time,
                    ipAddress=log.ip_address,
                    clientApp=log.app_display_name,
                    city=log.location.city,
                    state=log.location.state,
                    country=log.location.country_or_region,
                )
                log_list.append(al)
            return log_list


    async def get_risky_users(self) -> list:
        """
        Gets a list of risky users and translates them into a structured format for later use
        :return: list of risky users
        :rtype: list
        """
        result = await self.client.identity_protection.risky_users.get()
        # this request returns a RiskyUserCollectionResponse
        # value is a list of risky users
        risky_users = []
        if result.value:
            user_list = result.value
            for user in user_list:
                u = User(
                    id=user.id,
                    display_name=user.user_display_name,
                    risk_level=user.risk_level,
                    risk_state=user.risk_state,
                    risk_detail=user.risk_detail,
                    is_deleted=user.is_deleted,
                )
                risky_users.append(u)
        return risky_users

    def get_logs_for_selected_users(self, user_list) -> list:
        """
        Iterates through each user in the selected user list to collect audit logs
        :param user_list: list of selected user dicts
        :return: list of selected user dicts with audit logs for export
        """
        user_logs = []
        for user in user_list:
            user['logs'] = asyncio.run(self.entra_get_last_30d_sign_ins_for_userid(user.user_id))
            user_logs.append(user)
        return user_logs

    def export_user_audit_logs(self, user_audit_logs):
        """
        Uses the provided user audit log dicts to create an excel workbook containing the previous
        30 days of entra audit logs for each selected user
        :param user_audit_logs:
        :return: None
        """
        with pd.ExcelWriter('risky_audit_logs.xlsx', engine='openpyxl') as writer:
            for user in user_audit_logs:
                user_df = pd.DataFrame(user['logs'])
                user_df.to_excel(writer, sheet_name=user['user_name'])


    def run(self):
        # If this is able to log in, my thought process is use a list of risk detections
        # and risky users to have a general baseline of users at risk for compromise
        # which might warrant further review. This would get those users
        # and obtain the previous 30 days of entra audit logs.
        # This could be expanded and combined with an IP geolocation API like ipinfo
        # to provide a high level view of logins which could lead to a deeper investigation
        # of the potentially compromised user's UALs
        users_to_check = []
        risk_detections = asyncio.run(self.get_risk_detections())
        risky_users = asyncio.run(self.get_risky_users())
        for detection in risk_detections:
            if not any(d['user_id'] == detection.user_id for d in users_to_check):
                user = {
                    'user_id': detection.user_id,
                    'user_name': detection.user_display_name
                }
                users_to_check.append(user)
        for user in risky_users:
            if not any(d['user_id'] == user.user_id for d in users_to_check):
                user = {
                    'user_id': user.user_id,
                    'user_name': user.user_display_name
                }
                users_to_check.append(user)
        user_audit_logs = self.get_logs_for_selected_users(users_to_check)
        self.export_user_audit_logs(user_audit_logs)



if __name__ == "__main__":
    user_input = {
        'tenant_id': 'testtenantid',
        'client_id': 'testclientid',
        'client_secret': 'testclientsecret'
    }
    collector = RiskyLogCollector(user_input)
    collector.run()