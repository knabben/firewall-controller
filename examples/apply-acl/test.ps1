# PowerShell script for testing HCN ACL rules on Windows
# Run as Administrator

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("setup", "apply", "verify", "remove", "cleanup", "all")]
    [string]$Action = "all"
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "    ✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "    ✗ $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Setup-TestEnvironment {
    Write-Step "Setting up test environment"

    if (-not (Test-Administrator)) {
        Write-Error "This script must be run as Administrator"
        exit 1
    }

    # Check if Docker is available
    try {
        docker version | Out-Null
        Write-Success "Docker is available"
    } catch {
        Write-Error "Docker is not available or not running"
        exit 1
    }

    # Create a test container if none exist
    $containers = docker ps -q
    if ($containers.Count -eq 0) {
        Write-Step "Creating test container..."
        docker run -d --name hcn-test-container mcr.microsoft.com/windows/nanoserver:ltsc2022 ping -t localhost
        Start-Sleep -Seconds 5
        Write-Success "Test container created"
    } else {
        Write-Success "Existing containers found"
    }
}

function Build-Example {
    Write-Step "Building apply-acl example"

    if (Test-Path ".\apply-acl.exe") {
        Remove-Item ".\apply-acl.exe" -Force
    }

    go build -o apply-acl.exe .

    if (Test-Path ".\apply-acl.exe") {
        Write-Success "Binary built successfully"
    } else {
        Write-Error "Failed to build binary"
        exit 1
    }
}

function Apply-ACLRules {
    Write-Step "Applying ACL rules"

    .\apply-acl.exe -action apply -policy "test/example-policy" -verbose

    if ($LASTEXITCODE -eq 0) {
        Write-Success "ACL rules applied successfully"
    } else {
        Write-Error "Failed to apply ACL rules"
        exit 1
    }
}

function Verify-ACLRules {
    Write-Step "Verifying ACL rules"

    # List tracked policies
    Write-Host "`n  Tracked policies:" -ForegroundColor Yellow
    .\apply-acl.exe -action list

    # List HCN endpoints
    Write-Host "`n  HCN endpoints:" -ForegroundColor Yellow
    .\apply-acl.exe -action list-endpoints

    # Use native PowerShell to verify
    Write-Host "`n  Native HCN verification:" -ForegroundColor Yellow
    $endpoints = Get-HnsEndpoint

    foreach ($ep in $endpoints) {
        Write-Host "    Endpoint: $($ep.Name) ($($ep.Id))"

        $policies = $ep.Policies | ConvertFrom-Json
        $aclPolicies = $policies | Where-Object { $_.Type -eq "ACL" }

        Write-Host "      ACL Policies: $($aclPolicies.Count)"

        foreach ($policy in $aclPolicies) {
            $settings = $policy.Settings | ConvertFrom-Json
            Write-Host "        - Direction: $($settings.Direction), Protocol: $($settings.Protocols), Priority: $($settings.Priority)"
        }
    }

    Write-Success "Verification complete"
}

function Remove-ACLRules {
    Write-Step "Removing ACL rules"

    .\apply-acl.exe -action remove -policy "test/example-policy" -verbose

    if ($LASTEXITCODE -eq 0) {
        Write-Success "ACL rules removed successfully"
    } else {
        Write-Error "Failed to remove ACL rules"
        exit 1
    }
}

function Cleanup-TestEnvironment {
    Write-Step "Cleaning up test environment"

    # Remove test container
    $container = docker ps -a --filter "name=hcn-test-container" -q
    if ($container) {
        docker rm -f $container | Out-Null
        Write-Success "Test container removed"
    }

    # Remove binary
    if (Test-Path ".\apply-acl.exe") {
        Remove-Item ".\apply-acl.exe" -Force
        Write-Success "Binary removed"
    }
}

# Main execution
try {
    switch ($Action) {
        "setup" {
            Setup-TestEnvironment
            Build-Example
        }
        "apply" {
            Apply-ACLRules
        }
        "verify" {
            Verify-ACLRules
        }
        "remove" {
            Remove-ACLRules
        }
        "cleanup" {
            Cleanup-TestEnvironment
        }
        "all" {
            Setup-TestEnvironment
            Build-Example
            Apply-ACLRules
            Verify-ACLRules
            Remove-ACLRules
            Cleanup-TestEnvironment
        }
    }

    Write-Host "`n✓ All steps completed successfully!`n" -ForegroundColor Green

} catch {
    Write-Host "`n✗ Error: $_`n" -ForegroundColor Red
    exit 1
}
