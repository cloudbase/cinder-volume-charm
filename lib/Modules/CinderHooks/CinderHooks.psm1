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

function New-ExeServiceWrapper {
    $pythonDir = Get-PythonDir -InstallDir $CINDER_INSTALL_DIR
    $python = Join-Path $pythonDir "python.exe"
    $updateWrapper = Join-Path $pythonDir "Scripts\UpdateWrappers.py"
    $cmd = @($python, $updateWrapper, "cinder-volume = cinder.cmd.volume:main")
    Invoke-JujuCommand -Command $cmd
}

function Get-CharmServices {
    $openstackVersion = Get-OpenstackVersion
    $pythonDir = Get-PythonDir -InstallDir $CINDER_INSTALL_DIR
    $pythonExe = Join-Path $pythonDir "python.exe"
    $cinderScript = Join-Path $pythonDir "Scripts\cinder-volume-script.py"
    $serviceWrapperCinderSMB = Get-ServiceWrapper -Service "CinderSMB" -InstallDir $CINDER_INSTALL_DIR
    $cinderSMBConfig = Join-Path $CINDER_INSTALL_DIR "etc\cinder\cinder-smb.conf"
    # NOTE(ibalutoiu):
    # Only 'CinderISCSI' should be specified, but the Mitaka MSI doesn't
    # generate it due to a known bug and only 'CinderSMB' wrapper is present.
    try {
        $serviceWrapperCinderISCSI = Get-ServiceWrapper -Service "CinderISCSI" -InstallDir $CINDER_INSTALL_DIR
    } catch {
        $serviceWrapperCinderISCSI = Get-ServiceWrapper -Service "CinderSMB" -InstallDir $CINDER_INSTALL_DIR
    }
    $cinderISCSIConfig = Join-Path $CINDER_INSTALL_DIR "etc\cinder\cinder-iscsi.conf"
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
                }
            )
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
                }
            )
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
    $sharesConfigFile = Join-Path $CINDER_INSTALL_DIR "etc\cinder\smbfs_shares_list"
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
    $configDir = Join-Path $CINDER_INSTALL_DIR "etc\cinder"
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
    [String[]]$enabledBackends = Get-EnabledBackends
    if($CINDER_SMB_BACKEND_NAME -in $enabledBackends) {
        $serviceNames += $charmServices['cinder-smb']['service']
    }
    if($CINDER_ISCSI_BACKEND_NAME -in $enabledBackends) {
        $serviceNames += $charmServices['cinder-iscsi']['service']
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

function Invoke-InstallHook {
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
    $renameReboot = Rename-JujuUnit
    if ($renameReboot) {
        Invoke-JujuReboot -Now
    }
    Install-Cinder
}

function Invoke-StopHook {
    Uninstall-Cinder
}

function Invoke-ConfigChangedHook {
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

function Invoke-MySQLDBRelationJoinedHook {
    $database, $databaseUser = Get-MySQLConfig
    $settings = @{
        'database' = $database
        'username' = $databaseUser
        'hostname' = Get-JujuUnitPrivateIP
    }
    $rids = Get-JujuRelationIds 'mysql-db'
    foreach ($r in $rids) {
        Set-JujuRelation -Settings $settings -RelationId $r
    }
}
