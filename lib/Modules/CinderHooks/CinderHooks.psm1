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

Import-Module OpenStackCommon
Import-Module JujuHelper
Import-Module JujuHooks
Import-Module JujuUtils
Import-Module JujuWindowsUtils
Import-Module ADCharmUtils
Import-Module WSFCCharmUtils


function Get-ReadOnlyConfigs {
    $leaderData = Get-LeaderData
    if(!$leaderData['read-only-configs']) {
        return @{}
    }
    return (Get-UnmarshaledObject $leaderData['read-only-configs'])
}

function Set-DomainUserOnServices {
    $adCtxt = Get-ActiveDirectoryContext
    if(!$adCtxt["adcredentials"]) {
        Write-JujuWarning "AD user credentials are not already set"
        return
    }
    $adUser = $adCtxt["adcredentials"][0]["username"]
    $adUserPassword = $adCtxt["adcredentials"][0]["password"]
    Grant-PrivilegesOnDomainUser -Username $adUser
    [String[]]$cinderServices = Get-CinderServiceNames
    foreach($svcName in $cinderServices) {
        Write-JujuInfo "Setting AD user for service '$svcName'"
        $svc = Get-Service $svcName
        $currState = $svc.Status
        Stop-Service $svcName
        Set-ServiceLogon -Services $svcName -UserName $adUser -Password $adUserPassword

        if ($currState -eq "Running" -and $svc.StartType -ne "Disabled") {
            Start-Service $svcName
        }
    }
}

function Set-ReadOnlyConfigs {
    $leaderData = Get-LeaderData 'read-only-configs'
    if($leaderData['read-only-configs']) {
        Write-JujuWarning "Read only configs are already set"
        return
    }
    if(!(Confirm-Leader)) {
        Write-JujuWarning "Unit is not leader. Cannot set read only configs"
        return
    }
    $configs = @{}
    $cfg = Get-JujuCharmConfig
    $readonlyConfigs = @(
        'db-prefix')
    foreach($i in $readonlyConfigs) {
        if($cfg[$i] -eq $null) {
            Throw "Config option $i cannot be null"
        }
        $configs[$i] = $cfg[$i]
    }
    Set-LeaderData -Settings @{
        'read-only-configs' = Get-MarshaledObject $configs
    }
}

function Get-CinderBackupContext {
    $requiredCtxt =  @{
        "cinder_backup_config" = $null;
    }
    $ctxt = Get-JujuRelationContext -Relation "cinder-backup" -RequiredContext $requiredCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    return $ctxt
}


function Get-EnabledBackends {
    $cfg = Get-JujuCharmConfig
    if(!$cfg['enabled-backends']) {
        # Defaults to only iscsi backend with local storage
        return @($ISCSI_BACKEND_NAME)
    }
    $backends = $cfg['enabled-backends'].Split() | Where-Object { $_ -ne "" }
    foreach($b in $backends) {
        if($b -notin $CINDER_VALID_BACKENDS) {
            Throw "'$b' is not a valid backend."
        }
    }
    return $backends
}

function Enable-MPIO {
    $cfg = Get-JujuCharmConfig
    if (!$cfg['enable-multipath-io']) {
        return $false
    }
    $mpioState = Get-WindowsOptionalFeature -Online -FeatureName MultiPathIO
    if ($mpioState.State -like "Enabled") {
        Write-JujuWarning "MPIO already enabled"
        $autoClaim = Get-MSDSMAutomaticClaimSettings
        if (!$autoclaim.iSCSI) {
            Enable-MSDSMAutomaticClaim -BusType iSCSI -ErrorAction SilentlyContinue
        }
        return $false
    }
    Write-JujuWarning "Enabling MultiPathIO feature"
    Enable-WindowsOptionalFeature -Online -FeatureName MultiPathIO -NoRestart -ErrorAction SilentlyContinue
    return $true
}

function New-ExeServiceWrapper {
    $pythonDir = Get-PythonDir -InstallDir $CINDER_INSTALL_DIR
    $python = Join-Path $pythonDir "python.exe"
    $updateWrapper = Join-Path $pythonDir "Scripts\UpdateWrappers.py"
    $cmd = @($python, $updateWrapper, "cinder-volume = cinder.cmd.volume:main")
    Invoke-JujuCommand -Command $cmd
    $cmd = @($python, $updateWrapper, "cinder-backup = cinder.cmd.backup:main")
    Invoke-JujuCommand -Command $cmd
}

function Get-CharmServices {
    $openstackVersion = Get-OpenstackVersion
    $pythonDir = Get-PythonDir -InstallDir $CINDER_INSTALL_DIR
    $pythonExe = Join-Path $pythonDir "python.exe"
    $cinderScript = Join-Path $pythonDir "Scripts\cinder-volume-script.py"
    $cinderBackupScript = Join-Path $pythonDir "Scripts\cinder-backup-script.py"
    
    $serviceWrapperCinderSMB = Get-ServiceWrapper -Service "CinderSMB" -InstallDir $CINDER_INSTALL_DIR

    $cinderSMBConfig = Join-Path $CINDER_INSTALL_DIR "etc\cinder-smb.conf"
    $cinderISCSIConfig = Join-Path $CINDER_INSTALL_DIR "etc\cinder-iscsi.conf"

    # NOTE(ibalutoiu):
    # Only 'CinderISCSI' should be specified, but the Mitaka MSI doesn't
    # generate it due to a known bug and only 'CinderSMB' wrapper is present.
    try {
        $serviceWrapperCinderISCSI = Get-ServiceWrapper -Service "CinderISCSI" -InstallDir $CINDER_INSTALL_DIR
    } catch {
        $serviceWrapperCinderISCSI = Get-ServiceWrapper -Service "CinderSMB" -InstallDir $CINDER_INSTALL_DIR
    }
    $clusterServiceCtx = Get-ClusterServiceContext

    $jujuCharmServices = @{
        'cinder-smb' = @{
            "template" = "$openstackVersion\cinder-smb.conf"
            "service" = $CINDER_VOLUME_SMB_SERVICE_NAME
            "service_bin_path" = "`"$serviceWrapperCinderSMB`" cinder-volume-smb `"$pythonExe`" `"$cinderScript`" --config-file `"$cinderSMBConfig`""
            "config" = "$cinderSMBConfig"
            "description" = "Service wrapper for OpenStack Cinder Volume"
            "display_name" = "OpenStack Cinder Volume Service (SMB)"
            "context_generators" = @(
                @{
                    "generator" = (Get-Item "function:Get-CinderBackupContext").ScriptBlock
                    "relation" = "cinder-backup"
                    "mandatory" = $false
                },
                @{
                    "generator" = (Get-Item "function:Get-MySQLContext").ScriptBlock
                    "relation" = "mysql-db"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-RabbitMQContext").ScriptBlock
                    "relation" = "amqp"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-GlanceContext").ScriptBlock
                    "relation" = "image-service"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-CharmConfigContext").ScriptBlock
                    "relation" = "config"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-SystemContext").ScriptBlock
                    "relation" = "system"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-SMBShareContext").ScriptBlock
                    "relation" = "smb-share"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-EtcdContext").ScriptBlock
                    "relation" = "etcd"
                    "mandatory" = ($clusterServiceCtx.Count -gt 0)
                },
                @{
                    "generator" = (Get-Item "function:Get-KeystoneCredentialsContext").ScriptBlock
                    "relation" = "keystone"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-CertificatesContext").ScriptBlock
                    "relation" = "certificates"
                }
            )
        }
        'cinder-backup-smb' = @{
            "service" = $CINDER_BACKUP_SMB_SERVICE_NAME 
            "service_bin_path" = "`"$serviceWrapperCinderSMB`" cinder-backup-smb `"$pythonExe`" `"$cinderBackupScript`" --config-file `"$cinderSMBConfig`""
            "config" = "$cinderSMBConfig"
            "description" = "Service wrapper for OpenStack Cinder Backup"
            "display_name" = "OpenStack Cinder Backup Service (SMB)"
            "context_generators" = @()
        }
        'cinder-iscsi' = @{
            "template" = "$openstackVersion\cinder-iscsi.conf"
            "service" = $CINDER_VOLUME_ISCSI_SERVICE_NAME
            "service_bin_path" = "`"$serviceWrapperCinderISCSI`" cinder-volume-iscsi `"$pythonExe`" `"$cinderScript`" --config-file `"$cinderISCSIConfig`""
            "config" = "$cinderISCSIConfig"
            "description" = "Service wrapper for OpenStack Cinder Volume"
            "display_name" = "OpenStack Cinder Volume Service (ISCSI)"
            "context_generators" = @(
                @{
                    "generator" = (Get-Item "function:Get-CinderBackupContext").ScriptBlock
                    "relation" = "cinder-backup"
                    "mandatory" = $false
                },
                @{
                    "generator" = (Get-Item "function:Get-MySQLContext").ScriptBlock
                    "relation" = "mysql-db"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-RabbitMQContext").ScriptBlock
                    "relation" = "amqp"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-GlanceContext").ScriptBlock
                    "relation" = "image-service"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-CharmConfigContext").ScriptBlock
                    "relation" = "config"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-SystemContext").ScriptBlock
                    "relation" = "system"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-EtcdContext").ScriptBlock
                    "relation" = "etcd"
                    "mandatory" = ($clusterServiceCtx.Count -gt 0)
                },
                @{
                    "generator" = (Get-Item "function:Get-KeystoneCredentialsContext").ScriptBlock
                    "relation" = "keystone"
                    "mandatory" = $true
                },
                @{
                    "generator" = (Get-Item "function:Get-CertificatesContext").ScriptBlock
                    "relation" = "certificates"
                }
            )
        }
        'cinder-backup-iscsi' = @{
            "service" = $CINDER_BACKUP_ISCSI_SERVICE_NAME 
            "service_bin_path" = "`"$serviceWrapperCinderISCSI`" cinder-backup-smb `"$pythonExe`" `"$cinderBackupScript`" --config-file `"$cinderISCSIConfig`""
            "config" = "$cinderSMBConfig"
            "description" = "Service wrapper for OpenStack Cinder Backup"
            "display_name" = "OpenStack Cinder Backup Service (iSCSI)"
            "context_generators" = @()
        }
    }

    return $jujuCharmServices
}

function Get-ClusterServiceRoleName {
    $cfg = Get-JujuCharmConfig
    if(!$cfg['cluster-role-name']) {
        Throw "Cluster service role name config option is not set"
    }
    return $cfg['cluster-role-name']
}

function Get-SMBShareContext {
    $requiredCtxt = @{
        "share" = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "smb-share" -RequiredContext $requiredCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    $sharesConfigFile = Join-Path $CINDER_INSTALL_DIR "etc\smbfs_shares_list"
    $shares = [string[]]$ctxt['share']
    [System.IO.File]::WriteAllLines($sharesConfigFile, $shares)
    return @{
        "shares_config_file" = "$sharesConfigFile"
    }
}

function Get-ClusterServiceContext {
    $requiredCtxt = @{
        'static-address' = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "cluster-service" `
                                    -RequiredContext $requiredCtxt
    if(!$ctxt) {
        return @{}
    }
    return $ctxt
}

function Get-CharmConfigContext {
    $ctxt = Get-ConfigContext
    if(!$ctxt['log_dir']) {
        $ctxt['log_dir'] = "$CINDER_DEFAULT_LOG_DIR"
    }
    if (!(Test-Path $ctxt['log_dir'])) {
        New-Item -ItemType Directory -Path $ctxt['log_dir']
    }
    if(!$ctxt['max_used_space_ratio']) {
        $ctxt['max_used_space_ratio'] = $CINDER_DEFAULT_MAX_USED_SPACE_RATIO
    }
    if(!$ctxt['oversubmit_ratio']) {
        $ctxt['oversubmit_ratio'] = $CINDER_DEFAULT_OVERSUBMIT_RATIO
    }
    if(!$ctxt['default_volume_format']) {
        $ctxt['default_volume_format'] = $CINDER_DEFAULT_DEFAULT_VOLUME_FORMAT
    }
    return $ctxt
}

function Get-CertificatesContext {
    Write-JujuWarning "Generating context for tls-certificates"

    $requiredCtx = @{
        "ca" = $null
    }

    $optionalCtx = @{
        "client.cert" = $null
        "client.key" = $null
    }

    $ctxt = Get-JujuRelationContext -Relation "certificates" `
                                    -OptionalContext $optionalCtx `
                                    -RequiredContext $requiredCtx

    if (!$ctxt.Count) {
        return @{}
    }

    Set-Content $CINDER_CA_CERT $ctxt["ca"]
    $ctxt["ssl_ca_cert"] = $CINDER_CA_CERT

    return $ctxt
}

function Get-KeystoneCredentialsContext {
    Write-JujuWarning "Generating context for keystone credentials"
    $requiredCtx = @{
        "credentials_project" = $null
        "credentials_project_id" = $null
        "credentials_host" = $null
        "credentials_port" = $null
        "credentials_protocol" = $null
        "credentials_username" = $null
        "credentials_password" = $null
        "credentials_project_domain_name" = $null
        "credentials_user_domain_name" = $null
        "region" = $null
        "api_version" = $null
    }

    $optionalCtx = @{
        "ca_cert" = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "keystone" `
                                    -OptionalContext $optionalCtx `
                                    -RequiredContext $requiredCtx

    if (!$ctxt.Count) {
        return @{}
    }

    if (!$ctxt["api_version"] -or $ctxt["api_version"] -eq 2) {
        $ctxt["api_version"] = "2.0"
    }

    $authurl = "{0}://{1}:{2}/v{3}/" -f @(
                            $ctxt['credentials_protocol'],
                            $ctxt['credentials_host'],
                            $ctxt['credentials_port'],
                            $ctxt['api_version']
                        )

    $ctxt["admin_auth_url"] = $authurl

    $ksCa = Join-Path $CINDER_INSTALL_DIR "etc\keystone_ca_cert.pem"

    if ($ctxt["ca_cert"]) {
        Write-FileFromBase64 -File $ksCa -Content $ctxt["ca_cert"]
        $ctxt["ks_ssl_ca_cert"] = $ksCa
    }

    return $ctxt
}

function Get-CloudComputeContext {
    Write-JujuWarning "Generating context for nova cloud controller"
    $required = @{
        "service_protocol" = $null
        "service_port" = $null
        "admin_domain_name" = $null
        "auth_host" = $null
        "auth_port" = $null
        "auth_protocol" = $null
        "service_tenant_name" = $null
        "service_username" = $null
        "service_password" = $null
        "region" = $null
        "api_version" = $null
    }
    $optionalCtx = @{
        "neutron_url" = $null
        "quantum_url" = $null
    }
    $ctx = Get-JujuRelationContext -Relation 'cloud-compute' -RequiredContext $required -OptionalContext $optionalCtx
    if (!$ctx.Count -or (!$ctx["neutron_url"] -and !$ctx["quantum_url"])) {
        Write-JujuWarning "Missing required relation settings for Neutron. Peer not ready?"
        return @{}
    }
    if (!$ctx["neutron_url"]) {
        $ctx["neutron_url"] = $ctx["quantum_url"]
    }
    $ctx["auth_strategy"] = "keystone"
    $ctx["admin_auth_uri"] = "{0}://{1}:{2}" -f @($ctx["service_protocol"], $ctx['auth_host'], $ctx['service_port'])
    $ctx["admin_auth_url"] = "{0}://{1}:{2}" -f @($ctx["auth_protocol"], $ctx['auth_host'], $ctx['auth_port'])
    return $ctx
}

function Get-SystemContext {
    $ctxt = @{
        'my_ip' = Get-JujuUnitPrivateIP
        'host' = [System.Net.Dns]::GetHostName()
        'lock_dir' = "$CINDER_DEFAULT_LOCK_DIR"
        'iscsi_lun_path' = "$CINDER_DEFAULT_ISCSI_LUN_DIR"
        'image_conversion_dir'= "$CINDER_DEFAULT_IMAGE_CONVERSION_DIR"
        'mount_point_base' = "$CINDER_DEFAULT_MOUNT_POINT_BASE_DIR"
    }
    $charmDirs = @(
        $ctxt['lock_dir'],
        $ctxt['iscsi_lun_path'],
        $ctxt['image_conversion_dir'],
        $ctxt['mount_point_base']
    )
    foreach($dir in $charmDirs) {
        if(!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir
        }
    }
    $cfg = Get-JujuCharmConfig
    if($cfg['hostname']) {
        $ctxt['host'] = $cfg['hostname']
    }
    $clusterSvcCtxt = Get-ClusterServiceContext
    if($clusterSvcCtxt['static-address']) {
        $ctxt['my_ip'] = $clusterSvcCtxt['static-address']
        $ctxt['host'] = Get-ClusterServiceRoleName
    }
    return $ctxt
}

function Install-CinderFromZip {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )

    if(Test-Path $CINDER_INSTALL_DIR) {
        Remove-Item -Recurse -Force $CINDER_INSTALL_DIR
    }
    Write-JujuWarning "Unzipping '$InstallerPath' to '$CINDER_INSTALL_DIR'"
    Expand-ZipArchive -ZipFile $InstallerPath -Destination $CINDER_INSTALL_DIR | Out-Null
    $configDir = Join-Path $CINDER_INSTALL_DIR "etc"
    if (!(Test-Path $configDir)) {
        New-Item -ItemType Directory $configDir | Out-Null
    }
    Add-ToSystemPath "$CINDER_INSTALL_DIR\Bin"
    New-ExeServiceWrapper | Out-Null
}

function Install-CinderFromMSI {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )

    $logFile = Join-Path $env:APPDATA "cinder-volume-installer-log.txt"
    $extraParams = @("SKIPCINDERCONF=1",
                     "INSTALLDIR=`"$CINDER_INSTALL_DIR`"",
                     "ISCSIDRIVER=1",
                     "SMBDRIVER=1")
    Install-Msi -Installer $installerPath -LogFilePath $logFile -ExtraArgs $extraParams
    # Delete default Windows services generated by the MSI installer.
    # Charm will generate the Windows services later on.
    $serviceNames = @(
        $CINDER_VOLUME_SERVICE_NAME,
        $CINDER_VOLUME_ISCSI_SERVICE_NAME,
        $CINDER_VOLUME_SMB_SERVICE_NAME
    )
    Remove-WindowsServices -Names $serviceNames
}

function Install-Cinder {
    Write-JujuWarning "Running Cinder install"
    $installerPath = Get-InstallerPath -Project 'Cinder'
    $installerExtension = $installerPath.Split('.')[-1]
    switch($installerExtension) {
        "zip" {
            Install-CinderFromZip $installerPath
        }
        "msi" {
            Install-CinderFromMSI $installerPath
        }
        default {
            Throw "Unknown installer extension: '$installerExtension'"
        }
    }
    $release = Get-OpenstackVersion
    Set-JujuApplicationVersion -Version $CINDER_PRODUCT[$release]['version']
    Set-CharmState -Namespace "cinder_volume" -Key "release_installed" -Value $release
    Remove-Item $installerPath
}

function Enable-RequiredWindowsFeatures {
    $requiredFeatures = @()
    $requiredServices = @()
    [String[]]$enabledBackends = Get-EnabledBackends
    if($CINDER_ISCSI_BACKEND_NAME -in $enabledBackends) {
        if(Get-IsNanoServer) {
            $requiredFeatures += 'iSCSITargetServer'
        } else {
            $requiredFeatures += 'FS-iSCSITarget-Server'
        }
        $requiredServices += @('wintarget', 'msiscsi')
    }
    if($requiredFeatures) {
        Install-WindowsFeatures -Features $requiredFeatures
    }
    foreach($service in $requiredServices) {
        Enable-Service -Name $service
        Start-Service -Name $service
    }
}

function New-CharmServices {
    $charmServices = Get-CharmServices
    foreach($key in $charmServices.Keys) {
        $service = Get-Service $charmServices[$key]["service"] -ErrorAction SilentlyContinue
        if(!$service) {
            New-Service -Name $charmServices[$key]["service"] `
                        -BinaryPathName $charmServices[$key]["service_bin_path"] `
                        -DisplayName $charmServices[$key]["display_name"] `
                        -Description $charmServices[$key]["description"] `
                        -Confirm:$false
            Set-Service $charmServices[$key]["service"] -StartupType Disabled
            Start-ExternalCommand { sc.exe failure $charmServices[$key]["service"] reset=5 actions=restart/1000 }
            Start-ExternalCommand { sc.exe failureflag $charmServices[$key]["service"] 1 }
            Stop-Service -Name $charmServices[$key]["service"]
        }
    }
}

function Get-ClusterServices {
    $services = @()
    [String[]]$serviceNames = Get-CinderServiceNames
    [String[]]$enabledBackends = Get-EnabledBackends
    if($CINDER_ISCSI_BACKEND_NAME -in $enabledBackends) {
        $serviceNames += 'WinTarget'
    }
    foreach ($serviceName in $serviceNames) {
        $service = Get-ManagementObject -Class Win32_Service -Filter "Name='$serviceName'"
        $serviceParams = $service.PathName -split ' '
        $startupParams = $serviceParams[1..($serviceParams.Length)]
        $services += @{
            'ServiceName' = $service.Name
            'DisplayName' = $service.DisplayName
            'StartupParameters' = $startupParams -join ' '
        }
    }
    return $services
}

function Get-CinderServiceNames {
    $charmServices = Get-CharmServices
    $serviceNames = @()
    $backupCtx = Get-CinderBackupContext
    Write-JujuWarning (ConvertTo-Json $backupCtx)
    [String[]]$enabledBackends = Get-EnabledBackends
    if($CINDER_SMB_BACKEND_NAME -in $enabledBackends) {
        $serviceNames += $charmServices['cinder-smb']['service']
        if ($backupCtx.Count -gt 0){
            $serviceNames += $charmServices['cinder-backup-smb']['service']
        }
    }
    if($CINDER_ISCSI_BACKEND_NAME -in $enabledBackends) {
        $serviceNames += $charmServices['cinder-iscsi']['service']
        if ($backupCtx.Count -gt 0){
            $serviceNames += $charmServices['cinder-backup-iscsi']['service']
        }
    }
    return $serviceNames
}

function New-CinderConfigFiles {
    [String[]]$enabledBackends = Get-EnabledBackends
    $charmServices = Get-CharmServices
    if($CINDER_SMB_BACKEND_NAME -in $enabledBackends) {
        $smbIncompleteRelations = New-ConfigFile -ContextGenerators $charmServices['cinder-smb']['context_generators'] `
                                                 -Template $charmServices['cinder-smb']['template'] `
                                                 -OutFile $charmServices['cinder-smb']['config']
    }
    if($CINDER_ISCSI_BACKEND_NAME -in $enabledBackends) {
        $iscsiIncompleteRelations = New-ConfigFile -ContextGenerators $charmServices['cinder-iscsi']['context_generators'] `
                                                   -Template $charmServices['cinder-iscsi']['template'] `
                                                   -OutFile $charmServices['cinder-iscsi']['config']
    }
    $incompleteRelations = $smbIncompleteRelations + $iscsiIncompleteRelations | Select-Object -Unique
    return $incompleteRelations
}

function Set-ClusterServiceRelation {
    [Array]$clusterServices = Get-ClusterServices
    $relationData = @{
        "computer-name" = [System.Net.Dns]::GetHostName()
        "role-name" = Get-ClusterServiceRoleName
        "services" = Get-MarshaledObject -Object $clusterServices
    }
    $rids = Get-JujuRelationIds -Relation 'cluster-service'
    foreach ($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $relationData
    }
}

function Uninstall-Cinder {
    $productNames = $CINDER_PRODUCT[$SUPPORTED_OPENSTACK_RELEASES].Name
    $productNames += $CINDER_PRODUCT['beta_name']
    $installedProductName = $null
    foreach($name in $productNames) {
        if(Get-ComponentIsInstalled -Name $name -Exact) {
            $installedProductName = $name
            break
        }
    }
    if($installedProductName) {
        Write-JujuWarning "Uninstalling '$installedProductName'"
        Uninstall-WindowsProduct -Name $installedProductName
    }
    $serviceNames = @(
        $CINDER_VOLUME_SERVICE_NAME,
        $CINDER_VOLUME_ISCSI_SERVICE_NAME,
        $CINDER_VOLUME_SMB_SERVICE_NAME
    )
    Remove-WindowsServices -Names $serviceNames
    if(Test-Path $CINDER_INSTALL_DIR) {
        Remove-Item -Recurse -Force $CINDER_INSTALL_DIR
    }
    Remove-CharmState -Namespace "cinder_volume" -Key "release_installed"
}

function Start-UpgradeOpenStackVersion {
    $installedRelease = Get-CharmState -Namespace "cinder_volume" -Key "release_installed"
    $release = Get-OpenstackVersion
    if($installedRelease -and ($installedRelease -ne $release)) {
        Write-JujuWarning "Upgrading Cinder from release '$installedRelease' to '$release'"
        Uninstall-Cinder
        Install-Cinder
    }
}


function Get-EtcdContext {
    Write-JujuWarning "Generating context for etcd"
    $required = @{
        "client_ca" = $null
        "client_cert" = $null
        "client_key" = $null
        "connection_string" = $null
    }
    $optionalCtx = @{
        "version" = $null
    }
    $ctx = Get-JujuRelationContext -Relation 'etcd' -RequiredContext $required -OptionalContext $optionalCtx
    if (!$ctx.Count) {
        Write-JujuWarning "Missing required relation settings from Etcd. Peer not ready?"
        return @{}
    }
    # Write etcd certs
    $etcd_ca_file = Join-Path $CINDER_INSTALL_DIR "etc\etcd-ca.crt"
    $etcd_cert_file = Join-Path $CINDER_INSTALL_DIR "etc\etcd-client.crt"
    $etcd_key_file = Join-Path $CINDER_INSTALL_DIR "etc\etcd-client.key"
    # Remove the current certificates (if any) and add the new ones
    Remove-Item -Recurse -Force "$etcd_ca_file" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$etcd_cert_file" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$etcd_key_file" -ErrorAction SilentlyContinue
    # Write the new certificates
    Set-Content $etcd_ca_file $ctx["client_ca"]
    Set-Content $etcd_cert_file $ctx["client_cert"]
    Set-Content $etcd_key_file $ctx["client_key"]
    # Get first url from the connection string
    $etcd_url = $ctx["connection_string"].Split(',')
    # Set additional contexts
    $ctx["backend_url"] = "etcd3+{0}?ca_cert={1}&cert_key={2}&cert_cert={3}" -f @($etcd_url[0], [uri]::EscapeUriString("$etcd_ca_file"), [uri]::EscapeUriString("$etcd_key_file"), [uri]::EscapeUriString("$etcd_cert_file"))
    return $ctx
}


function Invoke-InstallHook {
    Set-ReadOnlyConfigs
    if(!(Get-IsNanoServer)){
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true
        } catch {
            # No need to error out the hook if this fails.
            Write-JujuWarning "Failed to disable antivirus: $_"
        }
    }
    # Set machine to use high performance settings.
    try {
        Set-PowerProfile -PowerProfile Performance
    } catch {
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to set power scheme."
    }
    Start-TimeResync
    $mpioReboot = Enable-MPIO
    $renameReboot = Rename-JujuUnit
    if ($renameReboot -Or $mpioReboot) {
        Invoke-JujuReboot -Now
    }
    Install-Cinder
}

function Invoke-StopHook {
    Uninstall-Cinder
}

function Invoke-ConfigChangedHook {
    $mpioReboot = Enable-MPIO
    if ($mpioReboot) {
        Invoke-JujuReboot -Now
    }
    Set-DomainUserOnServices
    Enable-RequiredWindowsFeatures
    Start-UpgradeOpenStackVersion
    New-CharmServices
    $cfg = Get-JujuCharmConfig
    [String[]]$incompleteRelations = New-CinderConfigFiles
    if (!$incompleteRelations.Count) {
        Set-ClusterServiceRelation
        [String[]]$serviceNames = Get-CinderServiceNames
        if ($cfg['delay-service-start']) {
            $clusterServiceCtxt = Get-ClusterServiceContext
            if(!$clusterServiceCtxt.Count) {
                foreach($svc in $serviceNames) {
                    Set-Service -Name $svc -StartupType Manual
                    Stop-Service $svc
                }
                Set-JujuStatus -Status blocked -Message "Waiting for cluster-service relation"
            } else {
                foreach($svc in $serviceNames) {
                    Set-Service -Name $svc -StartupType Manual
                    # If service is running, it means that the cluster service
                    # was already created and we just need to restart the running
                    # cinder-volume agent in order to reload new the configuration file
                    $status = (Get-Service -Name $svc).Status
                    if($status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
                        Restart-Service -Name $svc
                    }
                }
                Set-JujuStatus -Status active -Message "Unit is ready"
            }
        } else {
            foreach($svc in $serviceNames) {
                # NOTE(ibalutoiu):
                # When 'hostname' config option is set, all the cinder volume
                # agents will report the same hostname and only the one
                # from the leader unit will be running. This is implemented
                # as a temporary workaround until Generic Cluster service role
                # is introduced in Windows Server Nano.
                if($cfg['hostname']) {
                    if(Confirm-Leader) {
                        Restart-Service $svc
                    } else {
                        Set-Service -Name $svc -StartupType Manual
                        Stop-Service $svc
                    }
                } else {
                    Set-Service -Name $svc -StartupType Automatic
                    Restart-Service $svc
                }
            }
            Set-JujuStatus -Status active -Message "Unit is ready"
        }
    } else {
        $msg = "Incomplete relations: {0}" -f @($incompleteRelations -join ', ')
        Set-JujuStatus -Status blocked -Message $msg
    }
}

function Invoke-SMBShareRelationJoinedHook {
    $adCtxt = Get-ActiveDirectoryContext
    if(!$adCtxt.Count -or !$adCtxt["adcredentials"]) {
        Write-JujuWarning "AD context is not complete yet"
        return
    }
    $accounts = @()
    $rids = Get-JujuRelationIds -Relation 'cinder-accounts'
    foreach($rid in $rids) {
        $units = Get-JujuRelatedUnits -RelationId $rid
        foreach($unit in $units) {
            $data = Get-JujuRelation -Unit $unit -RelationId $rid
            if(!$data['accounts']) {
                continue
            }
            $unmarshaledAccounts = Get-UnmarshaledObject $data['accounts']
            foreach($acc in $unmarshaledAccounts) {
                if($acc -notin $accounts) {
                    $accounts += $acc
                }
            }
        }
    }
    $cfg = Get-JujuCharmConfig
    $adGroup = "{0}\{1}" -f @($adCtxt['netbiosname'], $cfg['ad-computer-group'])
    if($adGroup -notin $accounts) {
        $accounts += $adGroup
    }
    $adUser = $adCtxt["adcredentials"][0]["username"]
    if($adUser -notin $accounts) {
        $accounts += $adUser
    }
    $marshalledAccounts = Get-MarshaledObject -Object $accounts
    $settings = @{
        "share-name" = "cinder-shares"
        "accounts" = $marshalledAccounts
    }
    $rids = Get-JujuRelationIds -Relation "smb-share"
    foreach ($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $settings
    }
}

function Invoke-CinderBackupRelationJoinedHook {
    $adCtxt = Get-ActiveDirectoryContext
    if(!$adCtxt.Count -or !$adCtxt["adcredentials"]) {
        Write-JujuWarning "AD context is not complete yet"
        return
    }

    $cfg = Get-JujuCharmConfig
    $adGroup = "{0}\{1}" -f @($adCtxt['netbiosname'], $cfg['ad-computer-group'])
    $adUser = $adCtxt["adcredentials"][0]["username"]
    $adPassword = $adCtxt["adcredentials"][0]["password"]

    $relationData = @{
        "ad_user" = $adUser;
        "ad_password" = $adPassword;
        "ad_group" = $adGroup;
        "ad_domain" = $adCtxt["domainName"];
    }

    $rids = Get-JujuRelationIds -Relation 'cinder-backup'
    foreach ($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $relationData
    }
}

function Invoke-CinderServiceRelationJoinedHook {
    $ctxt = Get-SystemContext
    [String[]]$enabledBackends = Get-EnabledBackends
    $relationSettings = @{
        'ip' = $ctxt['my_ip']
        'hostname' = $ctxt['hostname']
        'enabled-backends' = $enabledBackends -join ','
    }
    $rids = Get-JujuRelationIds -Relation "cinder-volume-service"
    foreach ($rid in $rids) {
        Set-JujuRelation -RelationId $rid -Settings $relationSettings
    }
}

function Invoke-WSFCRelationJoinedHook {
    $ctx = Get-ActiveDirectoryContext
    if(!$ctx.Count -or !(Confirm-IsInDomain $ctx["domainName"])) {
        Set-ClusterableStatus -Ready $false -Relation "failover-cluster"
        return
    }
    if (Get-IsNanoServer) {
        $features = @('FailoverCluster-NanoServer')
    } else {
        $features = @('Failover-Clustering', 'File-Services')
    }
    Install-WindowsFeatures -Features $features
    Set-ClusterableStatus -Ready $true -Relation "failover-cluster"
}

function Invoke-AMQPRelationJoinedHook {
    $username, $vhost = Get-RabbitMQConfig
    $relationSettings = @{
        'username' = $username
        'vhost' = $vhost
    }
    $rids = Get-JujuRelationIds -Relation "amqp"
    foreach ($rid in $rids){
        Set-JujuRelation -RelationId $rid -Settings $relationSettings
    }
}

function Get-MySQLContext {
    $cfg = Get-ReadOnlyConfigs
    $prefix = $cfg["db-prefix"]
    $passwdKey = "password"
    if ($prefix) {
        $passwdKey = "{0}_password" -f $prefix
    }
    $requiredCtxt = @{
        "db_host" = $null
        $passwdKey = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "mysql-db" -RequiredContext $requiredCtxt
    if(!$ctxt.Count) {
        return @{}
    }
    $database, $databaseUser = Get-MySQLConfig
    return @{
        'db_host' = $ctxt['db_host']
        'db_name' = $database
        'db_user' = $databaseUser
        'db_user_password' = $ctxt[$passwdKey]
    }
}

function Invoke-MySQLDBRelationJoinedHook {
    $database, $databaseUser = Get-MySQLConfig
    $cfg = Get-ReadOnlyConfigs
    $prefix = $cfg["db-prefix"]

    $dbKey = 'database'
    $userKey = 'username'
    $hostnameKey = 'hostname'
    if ($prefix) {
        $dbKey = '{0}_database' -f $prefix
        $userKey = '{0}_username' -f $prefix
        $hostnameKey = '{0}_hostname' -f $prefix
    }
    $settings = @{
        $dbKey = $database
        $userKey = $databaseUser
        $hostnameKey = Get-JujuUnitPrivateIP
    }
    $rids = Get-JujuRelationIds 'mysql-db'
    foreach ($r in $rids) {
        Set-JujuRelation -Settings $settings -RelationId $r
    }
}

