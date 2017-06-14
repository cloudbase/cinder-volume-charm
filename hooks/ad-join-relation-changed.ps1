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

$ErrorActionPreference = "Stop"

Import-Module JujuLogging


try {
    Import-Module ADCharmUtils
    Import-Module JujuHooks
    Import-Module WSFCCharmUtils
    Import-Module CinderHooks

    if(Start-JoinDomain) {
        $adCtxt = Get-ActiveDirectoryContext
        if(!$adCtxt["adcredentials"]) {
            Write-JujuWarning "AD user credentials are not already set"
            exit 0
        }
        $adUser = $adCtxt["adcredentials"][0]["username"]
        $adUserPassword = $adCtxt["adcredentials"][0]["password"]
        Grant-PrivilegesOnDomainUser -Username $adUser
        [String[]]$cinderServices = Get-CinderServiceNames
        foreach($svcName in $cinderServices) {
            Write-JujuInfo "Setting AD user for service '$svcName'"
            Stop-Service $svcName
            Set-ServiceLogon -Services $svcName -UserName $adUser -Password $adUserPassword
            Start-Service $svcName
        }
        Invoke-WSFCRelationJoinedHook
        Invoke-SMBShareRelationJoinedHook
        Invoke-ConfigChangedHook
    }
} catch {
    Write-HookTracebackToLog $_
    exit 1
}
