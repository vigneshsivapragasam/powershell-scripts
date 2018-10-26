##Powershell script to add mitigation post fix for Spectre/Meltdown
##https://support.microsoft.com/en-nz/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
##https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002

#REGISTRY PATHS
$FeatureSettingsOverrideregistryPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management"
$FeatureSettingsOverrideMaskregistryPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management"
$MinVmVersionForCpuBasedMitigationsregistryPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization"
$SEPMregistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\QualityCompat"

#REGISTRY NAMES
$FSOName1 = "FeatureSettingsOverride"
$FSOMName2 = "FeatureSettingsOverrideMask"
$MVVFCBMName3 = "MinVmVersionForCpuBasedMitigations"
$SEPMName = "cadca5fe-87d3-4b96-b7fb-a231484277cc"

#REGISTRY VALUES
$FSOvalue = "0"
$FSOMvalue = "3"
$MVVFCBMvalue = "1.0"
$SEPMvalue = "0"


## Function to add FeatureSettingsOverride
function Fix-FeatureSettingsOverrideregistryPath {
Write-Host "Checking for Fix on FeatureSettingsOverride...."	
	IF(!(Test-Path $FeatureSettingsOverrideregistryPath))
		{
	    	New-Item -Path $FeatureSettingsOverrideregistryPath -Force 
    		New-ItemProperty -Path $FeatureSettingsOverrideregistryPath -Name $FSOName1 -Value $FSOvalue `
    		-PropertyType DWORD -Force 
            Write-Host "FeatureSettingsOverride path created, and value fixed"
            Write-Host ""    		
		}

		ELSE {
			New-ItemProperty -Path $FeatureSettingsOverrideregistryPath -Name $FSOName1 -Value $FSOvalue `
    		-PropertyType DWORD -Force 
    		Write-Host "FeatureSettingsOverride value overriden and fixed"
    		Write-Host ""
		}

}

## Function to add FeatureSettingsOverrideMask
function Fix-FeatureSettingsOverrideMaskregistryPath {
Write-Host "Checking for Fix on FeatureSettingsOverrideMask...."
	IF(!(Test-Path $FeatureSettingsOverrideMaskregistryPath))
		{
    		New-Item -Path $FeatureSettingsOverrideMaskregistryPath -Force 
    		New-ItemProperty -Path $FeatureSettingsOverrideMaskregistryPath -Name $FSOMName2 -Value $FSOMvalue `
    		-PropertyType DWORD -Force 
            Write-Host "FeatureSettingsOverrideMask path created, and value fixed"
            Write-Host ""
		}

		ELSE {
    		New-ItemProperty -Path $FeatureSettingsOverrideMaskregistryPath -Name $FSOMName2 -Value $FSOMvalue `
    		-PropertyType DWORD -Force 
            Write-Host "FeatureSettingsOverrideMask value overriden and fixed"
            Write-Host ""
		}	

}

## Function to add MinVmVersionForCpuBasedMitigations for machines running on Hyper-V hypervisors
## https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/cve-2017-5715-and-hyper-v-vms
function MinVmVersionForCpuBasedMitigationsregistryPath {
Write-Host "Checking for Fix on MinVmVersionForCpuBasedMitigations...."	
	IF(Test-Path $MinVmVersionForCpuBasedMitigationsregistryPath)
		{
    		##New-Item -Path $MinVmVersionForCpuBasedMitigationsregistryPath -Force 
    		New-ItemProperty -Path $MinVmVersionForCpuBasedMitigationsregistryPath -Name $MVVFCBMName3 -Value $MVVFCBMvalue `
    		-PropertyType STRING -Force 
            Write-Host "MinVmVersionForCpuBasedMitigations fixed"
		}

		ELSE {
            Write-Host "MinVmVersionForCpuBasedMitigations not supported. Only for Azure deployments"
		}	

}

## Function to test if SEPM Keys need to be added
## https://support.microsoft.com/en-nz/help/4072699/january-3-2018-windows-security-updates-and-antivirus-software 
function Check-SEPMKeys {

            Write-Host "Checking for SEPMKeys..."
			$exists = Get-ItemProperty -Path $SEPMregistryPath -Name $SEPMName -ErrorAction SilentlyContinue
            IF([string]::IsNullorEmpty($exists)) 
                {
                    Write-Host "SEPM mitigation not needed, no antivirus installed. Moving on...."
                    Write-Host ""
                    Fix-FeatureSettingsOverrideregistryPath;
                    Fix-FeatureSettingsOverrideMaskregistryPath;            
                    MinVmVersionForCpuBasedMitigationsregistryPath;
                }
                ELSE {
                    Write-Host "Check-SEPMKeys: $exists"
                    Write-Host "Implementing fix for Anti-virus compatibility on server"
                    New-ItemProperty -Path $SEPMregistryPath -Name $SEPMName -Value $SEPMvalue `
                    -PropertyType STRING -Force
                    Fix-FeatureSettingsOverrideregistryPath;
                    Fix-FeatureSettingsOverrideMaskregistryPath;            
                    MinVmVersionForCpuBasedMitigationsregistryPath;
                }

}

Check-SEPMKeys