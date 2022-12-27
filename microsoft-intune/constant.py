""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

APP_Sharing_Level = {
    'None': 'none',
    'Policy Managed Apps': 'policyManagedApps',
    'All Apps': 'allApps'
}

Clipboard_Sharing_Level = {
    'Blocked': 'blocked',
    'Policy Managed Apps': 'policyManagedApps',
    'Policy Managed Apps With PasteIn': 'policyManagedAppsWithPasteIn',
    'All Apps': 'allApps'
}

File_Encryption_Level = {
    'Device Locked': 'deviceLocked',
    'Device Locked Exception Files Open': 'deviceLockedExceptFilesOpen',
    'Device Restart': 'afterDeviceRestart',
    'Device Settings': 'useDeviceSettings'
}

# authorization types
AUTH_BEHALF_OF_USER = "On behalf of User - Delegate Permission"
AUTH_USING_APP = "Without a User - Application Permission"