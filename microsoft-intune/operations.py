""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError
import json, random, string
from requests import request, exceptions as req_exceptions
from .microsoft_api_auth import *
from .constant import *

logger = get_logger('microsoft-intune')


def api_request(method, endpoint, connector_info, config, params=None, data=None, headers={}, flag=None):
    try:
        ms = MicrosoftAuth(config)
        endpoint = ms.host + "/" + API_VERSION + endpoint
        token = ms.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        headers['consistencylevel'] = 'eventual'
        try:
            response = request(method, endpoint, headers=headers, params=params, data=data, verify=ms.verify_ssl)
            if response.status_code in [200, 201, 202, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return dict()
            elif response.status_code == 404 and flag:
                raise ConnectorError('{0}'.format(response.content))
            elif response.status_code == 404:
                return {'message': 'Not Found'}
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
        elif value != '' and value is not None:
            updated_payload[key] = value
    return updated_payload


def list_managed_devices(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices"
    response = api_request("GET", endpoint, connector_info, config)
    return response


def get_managed_device_details(config, params, connector_info):
    managedDeviceId = params.pop('managedDeviceId')
    endpoint = "/deviceManagement/managedDevices/{0}".format(managedDeviceId)
    payload = check_payload(params)
    response = api_request("GET", endpoint, connector_info, config)
    return response


def retire_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/retire".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully retire device {0}".format(params.get('managedDeviceId'))}


def wipe_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/wipe".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully wipe a device {0}".format(params.get('managedDeviceId'))}


def reset_passcode_of_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/resetPasscode".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully reset passcode for a device {0}".format(params.get('managedDeviceId'))}


def remote_lock_of_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/remoteLock".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully remote lock for a device {0}".format(params.get('managedDeviceId'))}


def request_remote_assistance_of_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/requestRemoteAssistance".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {
            "message": "Successfully request remote assistance for a device {0}".format(params.get('managedDeviceId'))}


def disable_lost_mode_of_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/disableLostMode".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully disabled a lost mode for a device {0}".format(params.get('managedDeviceId'))}


def locate_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/locateDevice".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully locate a device {0}".format(params.get('managedDeviceId'))}


def bypass_activation_lock_of_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/bypassActivationLock".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully bypass activation lock of a device {0}".format(params.get('managedDeviceId'))}


def reboot_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/rebootNow".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully reboot of a device {0}".format(params.get('managedDeviceId'))}


def shutdown_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/shutDown".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully shutdown a device {0}".format(params.get('managedDeviceId'))}


def recover_passcode_of_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/recoverPasscode".format(params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully recover passcode of a device {0}".format(params.get('managedDeviceId'))}


def clean_windows_device(config, params, connector_info):
    managedDeviceId = params.pop('managedDeviceId')
    endpoint = "/deviceManagement/managedDevices/{0}/cleanWindowsDevice".format(managedDeviceId)
    payload = check_payload(params)
    response = api_request("POST", endpoint, connector_info, config, data=json.dumps(payload))
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully clean a windows device {0}".format(managedDeviceId)}


def logout_shared_apple_device_active_user(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/logoutSharedAppleDeviceActiveUser".format(
        params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {
            "message": "Successfully logout shared apple device active user {0}".format(params.get('managedDeviceId'))}


def delete_user_from_shared_apple_device(config, params, connector_info):
    managedDeviceId = params.pop('managedDeviceId')
    endpoint = "/deviceManagement/managedDevices/{0}/deleteUserFromSharedAppleDevice".format(managedDeviceId)
    payload = check_payload(params)
    response = api_request("POST", endpoint, connector_info, config, data=json.dumps(payload))
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully deleted a user from shared apple device {0}".format(managedDeviceId)}


def sync_device(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/syncDevice".format(
        params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {
            "message": "Successfully sync a device {0}".format(params.get('managedDeviceId'))}


def windows_defender_scan(config, params, connector_info):
    managedDeviceId = params.pop('managedDeviceId')
    endpoint = "/deviceManagement/managedDevices/{0}/windowsDefenderScan".format(managedDeviceId)
    payload = check_payload(params)
    response = api_request("POST", endpoint, connector_info, config, data=json.dumps(payload))
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully scan a device with windows defender {0}".format(managedDeviceId)}


def windows_defender_update_signature(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices/{0}/windowsDefenderUpdateSignatures".format(
        params.get('managedDeviceId'))
    response = api_request("POST", endpoint, connector_info, config)
    if response.get('message'):
        return response
    else:
        return {
            "message": "Successfully updated a signature of windows defender device {0}".format(
                params.get('managedDeviceId'))}


def update_windows_device_account(config, params, connector_info):
    managedDeviceId = params.pop('managedDeviceId')
    endpoint = "/deviceManagement/managedDevices/{0}/updateWindowsDeviceAccount".format(managedDeviceId)
    payload = check_payload(params)
    response = api_request("POST", endpoint, connector_info, config, data=json.dumps(payload))
    if response.get('message'):
        return response
    else:
        return {"message": "Successfully updated a windows device account {0}".format(managedDeviceId)}


def login(config, params, connector_info):
    endpoint = "/deviceManagement/managedDevices"
    response = api_request("GET", endpoint, connector_info, config, flag=1)
    return response


def _check_health(config, connector_info):
    try:
        if check(config, connector_info) and login(config, params={}, connector_info=connector_info):
            return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'list_managed_devices': list_managed_devices,
    'get_managed_device_details': get_managed_device_details,
    'retire_device': retire_device,
    'wipe_device': wipe_device,
    'reset_passcode_of_device': reset_passcode_of_device,
    'remote_lock_of_device': remote_lock_of_device,
    'request_remote_assistance_of_device': request_remote_assistance_of_device,
    'disable_lost_mode_of_device': disable_lost_mode_of_device,
    'locate_device': locate_device,
    'bypass_activation_lock_of_device': bypass_activation_lock_of_device,
    'reboot_device': reboot_device,
    'shutdown_device': shutdown_device,
    'recover_passcode_of_device': recover_passcode_of_device,
    'clean_windows_device': clean_windows_device,
    'logout_shared_apple_device_active_user': logout_shared_apple_device_active_user,
    'delete_user_from_shared_apple_device': delete_user_from_shared_apple_device,
    'sync_device': sync_device,
    'windows_defender_scan': windows_defender_scan,
    'windows_defender_update_signature': windows_defender_update_signature,
    'update_windows_device_account': update_windows_device_account
}
