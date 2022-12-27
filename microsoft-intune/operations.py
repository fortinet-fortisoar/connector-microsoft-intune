""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
from requests import exceptions as req_exceptions
from .microsoft_api_auth import *
from .constant import *
import json

logger = get_logger('microsoft-intune')


def api_request(method, endpoint, connector_info, config, params=None, data=None, json=None, headers={}):
    try:
        ms = MicrosoftAuth(config)
        endpoint = ms.host + endpoint
        token = ms.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        headers['consistencylevel'] = 'eventual'
        try:
            response = request(method, endpoint, headers=headers, params=params, data=data, json=json,
                               verify=ms.verify_ssl)
            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            elif response.status_code == 404:
                return response
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))
    except Exception as err:
        raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value:
            updated_payload[key] = value
    return updated_payload


def get_location_list(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations?api-version=2015-01-14-preview"
    response = api_request("GET", url, connector_info, config)
    return response


def get_location_by_hostname(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/hostName?api-version=2015-01-14-preview"
    response = api_request("GET", url, connector_info, config)
    return response


def get_manageable_apps(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/apps?api-version=2015-01-14-preview".format(
        params.get('hostName'))
    filter = params.get('$filter')
    if filter:
        filter = 'properties/' + filter
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$filter': filter,
        '$select': select,
        '$top': params.get('$top')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def get_flagged_user_list(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/flaggedUsers?api-version=2015-01-14-preview".format(
        params.get('hostName'))
    filter = params.get('$filter')
    if filter:
        filter = 'properties/' + filter
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$filter': filter,
        '$select': select,
        '$top': params.get('$top')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def get_flagged_user_details(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/flaggedUsers/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('userName'))
    payload = {
        '$select': params.get('$select')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def get_tenant_level_statuses(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/statuses/default?api-version=2015-01-14-preview".format(
        params.get('hostName'))
    response = api_request("GET", url, connector_info, config)
    return response


def get_devices_user_list(config, params, connector_info):
    url = "providers/Microsoft.Intune/locations/{0}/users/{1}/devices?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('userName'))
    filter = params.get('$filter')
    if filter:
        filter = 'properties/' + filter
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$filter': filter,
        '$select': select,
        '$top': params.get('$top')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def get_device_user_details(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/users/{1}/devices/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('userName'), params.get('deviceName'))
    payload = {
        '$select': params.get('$select')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def get_flagged_enrolled_app_list(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/flaggedUsers/{1}/flaggedEnrolledApps?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('userName'))
    filter = params.get('$filter')
    if filter:
        filter = 'properties/' + filter
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$filter': filter,
        '$select': select,
        '$top': params.get('$top')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def convert_string_to_lowercase(value):
    if value:
        if value == 'Not Required':
            return "notRequired"
        else:
            return value.lower()
    else:
        return ''


def add_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    payload = {
        'location': params.get('location'),
        'tags': params.get('tags'),
        'properties': {
            'friendlyName': params.get('friendlyName'),
            'accessRecheckOfflineTimeout': params.get('accessRecheckOfflineTimeout'),
            'accessRecheckOnlineTimeout	': params.get('accessRecheckOnlineTimeout'),
            'appSharingFromLevel': APP_Sharing_Level.get(params.get('appSharingFromLevel')) if params.get(
                'appSharingFromLevel') else '',
            'appSharingToLevel': APP_Sharing_Level.get(params.get('appSharingToLevel')) if params.get(
                'appSharingToLevel') else '',
            'authentication': convert_string_to_lowercase(params.get('authentication')),
            'clipboardSharingLevel': Clipboard_Sharing_Level(params.get('clipboardSharingLevel')) if params.get(
                'clipboardSharingLevel') else '',
            'dataBackup': convert_string_to_lowercase(params.get('dataBackup')),
            'description': params.get('description'),
            'deviceCompliance': convert_string_to_lowercase(params.get('deviceCompliance')),
            'fileEncryption': convert_string_to_lowercase(params.get('fileEncryption')),
            'fileSharingSaveAs': convert_string_to_lowercase(params.get('fileSharingSaveAs')),
            'managedBrowser': convert_string_to_lowercase(params.get('managedBrowser')),
            'offlineWipeTimeout': params.get('offlineWipeTimeout'),
            'pin': convert_string_to_lowercase(params.get('pin')),
            'pinNumRetry': params.get('pinNumRetry'),
            'screenCapture': convert_string_to_lowercase(params.get('screenCapture'))
        }
    }
    payload = check_payload(payload)
    response = api_request("POST", url, connector_info, config, data=json.dumps(payload))
    return response


def get_android_policies(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies?api-version=2015-01-14-preview".format(
        params.get('hostName'))
    filter = params.get('$filter')
    if filter:
        filter = 'properties/' + filter
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$filter': filter,
        '$select': select,
        '$top': params.get('$top')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def get_android_policy_by_name(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$select': select
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def update_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    payload = {
        'location': params.get('location'),
        'tags': params.get('tags'),
        'properties': {
            'friendlyName': params.get('friendlyName'),
            'accessRecheckOfflineTimeout': params.get('accessRecheckOfflineTimeout'),
            'accessRecheckOnlineTimeout	': params.get('accessRecheckOnlineTimeout'),
            'appSharingFromLevel': APP_Sharing_Level.get(params.get('appSharingFromLevel')) if params.get(
                'appSharingFromLevel') else '',
            'appSharingToLevel': APP_Sharing_Level.get(params.get('appSharingToLevel')) if params.get(
                'appSharingToLevel') else '',
            'authentication': convert_string_to_lowercase(params.get('authentication')),
            'clipboardSharingLevel': Clipboard_Sharing_Level(params.get('clipboardSharingLevel')) if params.get(
                'clipboardSharingLevel') else '',
            'dataBackup': convert_string_to_lowercase(params.get('dataBackup')),
            'description': params.get('description'),
            'deviceCompliance': convert_string_to_lowercase(params.get('deviceCompliance')),
            'fileEncryption': convert_string_to_lowercase(params.get('fileEncryption')),
            'fileSharingSaveAs': convert_string_to_lowercase(params.get('fileSharingSaveAs')),
            'managedBrowser': convert_string_to_lowercase(params.get('managedBrowser')),
            'offlineWipeTimeout': params.get('offlineWipeTimeout'),
            'pin': convert_string_to_lowercase(params.get('pin')),
            'pinNumRetry': params.get('pinNumRetry'),
            'screenCapture': convert_string_to_lowercase(params.get('screenCapture'))
        }
    }
    payload = check_payload(payload)
    response = api_request("PATCH", url, connector_info, config, data=json.dumps(payload))
    return response


def delete_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    response = api_request("DELETE", url, connector_info, config)
    return response


def add_app_to_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}/apps/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'), params.get('appName'))
    response = api_request("POST", url, connector_info, config)
    return response


def get_apps_for_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/AndroidPolicies/{1}/apps?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    filter = params.get('$filter')
    if filter:
        filter = 'properties/' + filter
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$filter': filter,
        '$select': select,
        '$top': params.get('$top')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def delete_app_for_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}/apps/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'), params.get('appName'))
    response = api_request("DELETE", url, connector_info, config)
    return response


def add_group_to_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}/groups/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'), params.get('groupId'))
    response = api_request("POST", url, connector_info, config)
    return response


def get_groups_for_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}/groups?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    response = api_request("GET", url, connector_info, config)
    return response


def delete_group_for_android_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/androidPolicies/{1}/groups/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'), params.get('groupId'))
    response = api_request("DELETE", url, connector_info, config)
    return response


def add_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    payload = {
        'location': params.get('location'),
        'tags': params.get('tags'),
        'properties': {
            'friendlyName': params.get('friendlyName'),
            'accessRecheckOfflineTimeout': params.get('accessRecheckOfflineTimeout'),
            'accessRecheckOnlineTimeout	': params.get('accessRecheckOnlineTimeout'),
            'appSharingFromLevel': APP_Sharing_Level.get(params.get('appSharingFromLevel')) if params.get(
                'appSharingFromLevel') else '',
            'appSharingToLevel': APP_Sharing_Level.get(params.get('appSharingToLevel')) if params.get(
                'appSharingToLevel') else '',
            'authentication': convert_string_to_lowercase(params.get('authentication')),
            'clipboardSharingLevel': Clipboard_Sharing_Level(params.get('clipboardSharingLevel')) if params.get(
                'clipboardSharingLevel') else '',
            'dataBackup': convert_string_to_lowercase(params.get('dataBackup')),
            'description': params.get('description'),
            'deviceCompliance': convert_string_to_lowercase(params.get('deviceCompliance')),
            'fileEncryptionLevel': File_Encryption_Level.get(params.get('fileEncryptionLevel')) if params.get(
                'fileEncryptionLevel') else '',
            'fileSharingSaveAs': convert_string_to_lowercase(params.get('fileSharingSaveAs')),
            'managedBrowser': convert_string_to_lowercase(params.get('managedBrowser')),
            'offlineWipeTimeout': params.get('offlineWipeTimeout'),
            'pin': convert_string_to_lowercase(params.get('pin')),
            'pinNumRetry': params.get('pinNumRetry'),
            'touchId': convert_string_to_lowercase(params.get('touchId'))
        }
    }
    payload = check_payload(payload)
    response = api_request("POST", url, connector_info, config, data=json.dumps(payload))
    return response


def get_ios_policies(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies?api-version=2015-01-14-preview".format(
        params.get('hostName'))
    filter = params.get('$filter')
    if filter:
        filter = 'properties/' + filter
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$filter': filter,
        '$select': select,
        '$top': params.get('$top')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def get_ios_policy_by_name(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$select': select
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def update_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    payload = {
        'location': params.get('location'),
        'tags': params.get('tags'),
        'properties': {
            'friendlyName': params.get('friendlyName'),
            'accessRecheckOfflineTimeout': params.get('accessRecheckOfflineTimeout'),
            'accessRecheckOnlineTimeout	': params.get('accessRecheckOnlineTimeout'),
            'appSharingFromLevel': APP_Sharing_Level.get(params.get('appSharingFromLevel')) if params.get(
                'appSharingFromLevel') else '',
            'appSharingToLevel': APP_Sharing_Level.get(params.get('appSharingToLevel')) if params.get(
                'appSharingToLevel') else '',
            'authentication': convert_string_to_lowercase(params.get('authentication')),
            'clipboardSharingLevel': Clipboard_Sharing_Level(params.get('clipboardSharingLevel')) if params.get(
                'clipboardSharingLevel') else '',
            'dataBackup': convert_string_to_lowercase(params.get('dataBackup')),
            'description': params.get('description'),
            'deviceCompliance': convert_string_to_lowercase(params.get('deviceCompliance')),
            'fileEncryptionLevel': File_Encryption_Level.get(params.get('fileEncryptionLevel')) if params.get(
                'fileEncryptionLevel') else '',
            'fileSharingSaveAs': convert_string_to_lowercase(params.get('fileSharingSaveAs')),
            'managedBrowser': convert_string_to_lowercase(params.get('managedBrowser')),
            'offlineWipeTimeout': params.get('offlineWipeTimeout'),
            'pin': convert_string_to_lowercase(params.get('pin')),
            'pinNumRetry': params.get('pinNumRetry'),
            'touchId': convert_string_to_lowercase(params.get('touchId'))
        }
    }
    payload = check_payload(payload)
    response = api_request("POST", url, connector_info, config, data=json.dumps(payload))
    return response


def delete_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    response = api_request("DELETE", url, connector_info, config)
    return response


def add_app_to_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}/apps/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'), params.get('appName'))
    response = api_request("POST", url, connector_info, config)
    return response


def get_apps_for_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}/apps?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    filter = params.get('$filter')
    if filter:
        filter = 'properties/' + filter
    select = params.get('$select')
    if select:
        select = 'properties/' + select
    payload = {
        '$filter': filter,
        '$select': select,
        '$top': params.get('$top')
    }
    payload = check_payload(payload)
    response = api_request("GET", url, connector_info, config, params=payload)
    return response


def delete_app_for_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}/apps/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'), params.get('appName'))
    response = api_request("DELETE", url, connector_info, config)
    return response


def add_group_to_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}/groups/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'), params.get('groupId'))
    response = api_request("POST", url, connector_info, config)
    return response


def get_groups_for_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}/groups?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'))
    response = api_request("GET", url, connector_info, config)
    return response


def delete_group_for_ios_policy(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/iosPolicies/{1}/groups/{2}?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('policyName'), params.get('groupId'))
    response = api_request("DELETE", url, connector_info, config)
    return response


def wipe_device_for_user(config, params, connector_info):
    url = "/providers/Microsoft.Intune/locations/{0}/users/{1}/devices/{2}/wipe?api-version=2015-01-14-preview".format(
        params.get('hostName'), params.get('userName'), params.get('deviceName'))
    response = api_request("POST", url, connector_info, config)
    return response


def _check_health(config, connector_info):
    try:
        if check(config, connector_info) and get_location_list(config, params={}, connector_info=connector_info):
            return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'get_location_list': get_location_list,
    'get_location_by_hostname': get_location_by_hostname,
    'get_manageable_apps': get_manageable_apps,
    'get_flagged_user_list': get_flagged_user_list,
    'get_flagged_user_details': get_flagged_user_details,
    'get_tenant_level_statuses': get_tenant_level_statuses,
    'get_devices_user_list': get_devices_user_list,
    'get_device_user_details': get_device_user_details,
    'get_flagged_enrolled_app_list': get_flagged_enrolled_app_list,
    'add_android_policy': add_android_policy,
    'get_android_policies': get_android_policies,
    'get_android_policy_by_name': get_android_policy_by_name,
    'update_android_policy': update_android_policy,
    'delete_android_policy': delete_android_policy,
    'add_app_to_android_policy': add_app_to_android_policy,
    'get_apps_for_android_policy': get_apps_for_android_policy,
    'delete_app_for_android_policy': delete_app_for_android_policy,
    'add_group_to_android_policy': add_group_to_android_policy,
    'get_groups_for_android_policy': get_groups_for_android_policy,
    'delete_group_for_android_policy': delete_group_for_android_policy,
    'add_ios_policy': add_ios_policy,
    'get_ios_policies': get_ios_policies,
    'get_ios_policy_by_name': get_ios_policy_by_name,
    'update_ios_policy': update_ios_policy,
    'delete_ios_policy': delete_ios_policy,
    'add_app_to_ios_policy': add_app_to_ios_policy,
    'get_apps_for_ios_policy': get_apps_for_ios_policy,
    'delete_app_for_ios_policy': delete_app_for_ios_policy,
    'add_group_to_ios_policy': add_group_to_ios_policy,
    'get_groups_for_ios_policy': get_groups_for_ios_policy,
    'delete_group_for_ios_policy': delete_group_for_ios_policy,
    'wipe_device_for_user': wipe_device_for_user
}
