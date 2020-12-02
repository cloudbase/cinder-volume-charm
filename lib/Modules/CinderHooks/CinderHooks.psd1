# Copyright 2016 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Module manifest for module 'CinderHooks'
#
# Generated by: Ionut-Madalin Balutoiu
#
# Generated on: 01-Mar-16
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'CinderHooks.psm1'

# Version number of this module.
ModuleVersion = '0.1'

# ID used to uniquely identify this module
GUID = '65ba4ad0-8920-4f97-b55c-755888e2962e'

# Author of this module
Author = 'Ionut-Madalin Balutoiu'

# Company or vendor of this module
CompanyName = 'Cloudbase Solutions SRL'

# Copyright statement for this module
Copyright = '(c) 2016 Ionut-Madalin Balutoiu. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Module with Cinder functions used in charm hooks'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

FunctionsToExport = @(
    'Invoke-InstallHook',
    'Invoke-StopHook',
    'Invoke-ConfigChangedHook',
    'Invoke-SMBShareRelationJoinedHook',
    'Invoke-CinderServiceRelationJoinedHook',
    'Invoke-WSFCRelationJoinedHook',
    'Invoke-AMQPRelationJoinedHook',
    'Invoke-MySQLDBRelationJoinedHook',
    'Get-CinderServiceNames',
    'Invoke-CinderBackupRelationJoinedHook',
    'Set-ReadOnlyConfigs')
}
