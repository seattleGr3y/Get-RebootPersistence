<#
The sample scripts are not supported under any Microsoft standard support 
program or service. The sample scripts are provided AS IS without warranty  
of any kind. Microsoft further disclaims all implied warranties including,  
without limitation, any implied warranties of merchantability or of fitness for 
a particular purpose. The entire risk arising out of the use or performance of  
the sample scripts and documentation remains with you. In no event shall 
Microsoft, its authors, or anyone Else involved in the creation, production, or 
delivery of the scripts be liable for any damages whatsoever (including, 
without limitation, damages for loss of business profits, business interruption, 
loss of business information, or other pecuniary loss) arising out of the use 
of or inability to use the sample scripts or documentation, even If Microsoft 
has been advised of the possibility of such damages 
#>
Function Invoke-UACBypass {

	New-Variable -Name Key
	New-Variable -Name PromptOnSecureDesktop_Name
	New-Variable -Name ConsentPromptBehaviorAdmin_Name

	Function Set-RegistryValue { 
	  [cmdletbinding(SupportsShouldProcess=$True,ConfirmImpact="Low")]
	  Param ($key, $name, $value, $type="Dword")
	  If ((Test-Path -Path $key) -Eq $false) { New-Item -ItemType Directory -Path $key | Out-Null } 
  		If ($pscmdlet.ShouldProcess($value)) {
		   Set-ItemProperty -Path $key -Name $name -Value $value -Type $type 
		}
	} 

	Function Get-RegistryValue($key, $value) { 
	   (Get-ItemProperty $key $value).$value 
	} 

	$Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
	$ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin"
	$PromptOnSecureDesktop_Name = "PromptOnSecureDesktop"

	<#
		Powershell run as administrator
		Level   UAC Description                            ConsentPromptBehaviorAdmin    PromptOnSecureDesktop
		 0		Never notIfy										 0							 0 
		 1		NotIfy me only(do not dim my desktop)				 5							 0
		 2		NotIfy me only(default)								 5							 1
		 3		Always notIfy										 2							 1
	#>
	Function Set-UACLevel() {
		[cmdletbinding(SupportsShouldProcess=$True,ConfirmImpact="Low")]
		Param([int]$Level= 0)

		New-Variable -Name PromptOnSecureDesktop_Value
		New-Variable -Name ConsentPromptBehaviorAdmin_Value

		If($Level -In 0, 1, 2, 3) {
			$ConsentPromptBehaviorAdmin_Value = 5
			$PromptOnSecureDesktop_Value = 1
			Switch ($Level) 
			{ 
			  0 {
				  $ConsentPromptBehaviorAdmin_Value = 0 
				  $PromptOnSecureDesktop_Value = 0
			  }
			}
			If ($pscmdlet.ShouldProcess($Value)) {
				Set-RegistryValue -Key $Key -Name $ConsentPromptBehaviorAdmin_Name -Value $ConsentPromptBehaviorAdmin_Value
				Set-RegistryValue -Key $Key -Name $PromptOnSecureDesktop_Name -Value $PromptOnSecureDesktop_Value
			}
		}
		Else{
			"No supported level"
		}
	
	}
	Set-UACLevel
}