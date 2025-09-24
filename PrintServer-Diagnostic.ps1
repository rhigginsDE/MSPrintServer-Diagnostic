#Requires -Version 5.1

<#
.SYNOPSIS
    Enterprise-Grade Print Server Diagnostic Tool with Full Visual Interface and Industry-Standard Features

.DESCRIPTION
    Comprehensive diagnostic tool for Windows Print Server infrastructure providing:
    - Complete network connectivity and DNS resolution testing
    - Parallel TCP port scanning with performance metrics
    - CIM/WMI session management with intelligent protocol fallback
    - Print services, shares, printers, and spool directory analysis
    - Event log retrieval and pattern analysis with alerting
    - Real-time progress tracking with visual feedback
    - Professional HTML dashboard with interactive elements
    - Multiple export formats (HTML, JSON, CSV) with automatic report opening
    - Optional GUI interface using Windows Forms
    - Comprehensive structured logging with file rotation
    - JSON configuration management with profiles
    - Industry-standard error handling with retry mechanisms and circuit breaker patterns
    - Cross-platform PowerShell compatibility (5.1 through 7.x)

.PARAMETER ServerFqdn
    Fully Qualified Domain Name of the print server to diagnose.
    Must be a valid FQDN format. Supports pipeline input.

.PARAMETER Ports
    Array of TCP ports to test for connectivity.
    Default includes standard Windows and printing service ports.

.PARAMETER ExtraPorts
    Additional ports to test beyond the standard set.

.PARAMETER EventCount
    Number of recent PrintService events to retrieve from the server.
    Valid range: 1-1000, default is 30.

.PARAMETER LogPath
    Directory path for diagnostic log files.
    Default: $PSScriptRoot\Reports

.PARAMETER ExportResults
    Switch to export detailed results to multiple formats (HTML, JSON, CSV).
    Automatically opens HTML report in default browser.

.PARAMETER ShowGui
    Switch to display results in a comprehensive GUI interface with real-time updates.

.PARAMETER ConfigPath
    Path to JSON configuration file for advanced customization.
    Default: .\PrintDiagConfig.json

.PARAMETER Detailed
    Performs comprehensive analysis including event logs, performance metrics, and security checks.

.PARAMETER Client
    Runs in client-side mode for non-administrative testing of local and network printers.
    This mode works with standard user privileges and focuses on client-accessible printer diagnostics.

.PARAMETER Parallel
    Enables parallel processing for improved performance on multiple targets.

.PARAMETER MaxThreads
    Maximum number of concurrent threads for parallel operations.
    Default: 10, Range: 1-50

.EXAMPLE
    .\PrintServer-Diagnostic.ps1 -ServerFqdn "print-server.domain.com"
    Performs standard diagnostics on the specified print server with console output.

.EXAMPLE
    .\PrintServer-Diagnostic.ps1 -ServerFqdn "your-printserver.domain.com" -ExportResults -ShowGui
    Comprehensive diagnostics with visual dashboard and professional reports.

.EXAMPLE
    .\PrintServer-Diagnostic.ps1 -ServerFqdn "print-server.domain.com" -Client -Detailed -ExportResults
    Client-side printer testing with detailed analysis and comprehensive reporting.

.EXAMPLE
    .\PrintServer-Diagnostic.ps1 -ServerFqdn "print-server.domain.com" -Client -ShowGui
    Client-side printer diagnostics with graphical interface - no admin rights required.

.EXAMPLE
    .\PrintServer-Diagnostic.ps1 -ServerFqdn "print-server.domain.com" -Detailed -ExtraPorts 9100,9101 -MaxThreads 15 -Parallel
    Advanced diagnostics with custom ports and optimized parallel processing.

.NOTES
    Author: Enhanced Print Server Diagnostic Tool
    Version: 2.1.0
    Requires: PowerShell 5.1+, elevated privileges recommended for advanced features
    Compatible: Windows Server 2012R2+, PowerShell 5.1-7.x

.LINK
    https://docs.microsoft.com/en-us/windows/win32/printdocs/print-spooler-api
#>

[CmdletBinding(DefaultParameterSetName = 'Standard')]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = 'Standard')]
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = 'Detailed')]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if ($_ -match '^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{1,61}[a-zA-Z0-9])?$') {
            return $true
        }
        throw "ServerFqdn must be a valid FQDN format"
    })]
    [string]$ServerFqdn,

    [ValidateRange(1, 65535)]
    [int[]]$Ports = @(80, 135, 139, 443, 445, 515, 593, 631, 5985, 5986, 9100),

    [ValidateRange(1, 65535)]
    [int[]]$ExtraPorts = @(),

    [ValidateRange(1, 1000)]
    [int]$EventCount = 30,

    [string]$LogPath = "$PSScriptRoot\Reports",

    [switch]$ExportResults,

    [switch]$ShowGui,

    [string]$ConfigPath = "$PSScriptRoot\PrintDiagConfig.json",

    [Parameter(ParameterSetName = 'Detailed')]
    [Parameter(ParameterSetName = 'Client')]
    [switch]$Detailed,

    [Parameter(ParameterSetName = 'Client')]
    [switch]$Client,

    [switch]$Parallel,

    [ValidateRange(1, 50)]
    [int]$MaxThreads = 10
)

# =============================================================================
# GLOBAL CONFIGURATION AND CONSTANTS
# =============================================================================

$script:DiagnosticVersion = "2.1.0"
$script:SessionId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)

# =============================================================================
# FACTORY FUNCTIONS FOR OBJECT CREATION (CROSS-VERSION COMPATIBILITY)
# =============================================================================

function New-DiagnosticLogger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogDirectory,
        [bool]$WriteToConsole = $true,
        [bool]$WriteToFile = $true,
        [string]$LogLevel = 'INFO'
    )

    if ($WriteToFile -and -not (Test-Path $LogDirectory)) {
        try {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        catch {
            Write-Warning "Could not create log directory: $LogDirectory"
            $WriteToFile = $false
        }
    }

    $logger = [PSCustomObject]@{
        PSTypeName = 'PrintServerDiagnostic.Logger'
        LogDirectory = $LogDirectory
        LogFileName = "PrintServerDiag_$script:SessionId_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        WriteToConsole = $WriteToConsole
        WriteToFile = $WriteToFile
        LogLevel = $LogLevel
        SessionId = $script:SessionId
    }

    # Add logging methods
    $logger | Add-Member -MemberType ScriptMethod -Name WriteLog -Value {
        param([string]$level, [string]$message, [object]$data = $null, [string]$category = 'General')

        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $logEntry = "[$timestamp] [$($this.SessionId)] [$level] [$category] $message"

        if ($data) {
            try {
                $logEntry += " | Data: $($data | ConvertTo-Json -Compress -Depth 3 -ErrorAction SilentlyContinue)"
            }
            catch {
                $logEntry += " | Data: [Complex Object - $($data.GetType().Name)]"
            }
        }

        if ($this.WriteToConsole) {
            $color = switch ($level) {
                'ERROR' { 'Red' }
                'WARN' { 'Yellow' }
                'INFO' { 'Green' }
                'DEBUG' { 'Gray' }
                default { 'White' }
            }
            Write-Host $logEntry -ForegroundColor $color
        }

        if ($this.WriteToFile) {
            try {
                $logFilePath = Join-Path $this.LogDirectory $this.LogFileName
                $logEntry | Add-Content -Path $logFilePath -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            catch {
                # Silently fail if logging to file fails to prevent infinite loops
            }
        }
    }

    # Add convenience methods
    $logger | Add-Member -MemberType ScriptMethod -Name WriteInfo -Value {
        param([string]$message, [object]$data = $null, [string]$category = 'General')
        $this.WriteLog('INFO', $message, $data, $category)
    }

    $logger | Add-Member -MemberType ScriptMethod -Name WriteWarning -Value {
        param([string]$message, [object]$data = $null, [string]$category = 'General')
        $this.WriteLog('WARN', $message, $data, $category)
    }

    $logger | Add-Member -MemberType ScriptMethod -Name WriteError -Value {
        param([string]$message, [object]$data = $null, [string]$category = 'General')
        $this.WriteLog('ERROR', $message, $data, $category)
    }

    $logger | Add-Member -MemberType ScriptMethod -Name WriteDebug -Value {
        param([string]$message, [object]$data = $null, [string]$category = 'General')
        if ($VerbosePreference -eq 'Continue' -or $DebugPreference -eq 'Continue') {
            $this.WriteLog('DEBUG', $message, $data, $category)
        }
    }

    return $logger
}

function New-ProgressTracker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$TotalSteps,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Activity,

        [int]$Id = 1
    )

    $tracker = [PSCustomObject]@{
        PSTypeName = 'PrintServerDiagnostic.ProgressTracker'
        TotalSteps = $TotalSteps
        CurrentStep = 0
        Activity = $Activity
        Id = $Id
        StartTime = Get-Date
        StepDetails = @{}
        LastUpdateTime = Get-Date
    }

    $tracker | Add-Member -MemberType ScriptMethod -Name UpdateProgress -Value {
        param(
            [Parameter(Mandatory)]
            [string]$Status,
            [string]$CurrentOperation = '',
            [switch]$NoIncrement
        )

        if (-not $NoIncrement) {
            $this.CurrentStep++
        }

        $PercentComplete = [math]::Round(($this.CurrentStep / $this.TotalSteps) * 100, 1)
        if ($PercentComplete -gt 100) { $PercentComplete = 100 }

        # Calculate time estimates
        $elapsed = (Get-Date) - $this.StartTime
        $averageTimePerStep = if ($this.CurrentStep -gt 0) { $elapsed.TotalSeconds / $this.CurrentStep } else { 0 }
        $remainingSteps = $this.TotalSteps - $this.CurrentStep
        $estimatedRemainingSeconds = $remainingSteps * $averageTimePerStep

        $progressParams = @{
            Id = $this.Id
            Activity = $this.Activity
            Status = $Status
            PercentComplete = $PercentComplete
            CurrentOperation = $CurrentOperation
        }

        if ($estimatedRemainingSeconds -gt 0 -and $estimatedRemainingSeconds -lt 3600) {
            $progressParams.SecondsRemaining = [int]$estimatedRemainingSeconds
        }

        Write-Progress @progressParams

        $this.StepDetails[$this.CurrentStep] = @{
            Status = $Status
            Operation = $CurrentOperation
            Timestamp = Get-Date
            PercentComplete = $PercentComplete
        }

        $this.LastUpdateTime = Get-Date
    }

    $tracker | Add-Member -MemberType ScriptMethod -Name CompleteProgress -Value {
        Write-Progress -Id $this.Id -Activity $this.Activity -Completed
    }

    $tracker | Add-Member -MemberType ScriptMethod -Name GetSummary -Value {
        $elapsed = (Get-Date) - $this.StartTime
        return @{
            TotalSteps = $this.TotalSteps
            CompletedSteps = $this.CurrentStep
            PercentComplete = [math]::Round(($this.CurrentStep / $this.TotalSteps) * 100, 2)
            ElapsedTime = $elapsed
            AverageTimePerStep = if ($this.CurrentStep -gt 0) { $elapsed.TotalSeconds / $this.CurrentStep } else { 0 }
            EstimatedTimeRemaining = if ($this.CurrentStep -gt 0) {
                $remaining = $this.TotalSteps - $this.CurrentStep
                [timespan]::FromSeconds($remaining * ($elapsed.TotalSeconds / $this.CurrentStep))
            } else { [timespan]::Zero }
        }
    }

    return $tracker
}

function New-DiagnosticResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServerName
    )

    $result = [PSCustomObject]@{
        PSTypeName = 'PrintServerDiagnostic.Result'
        ServerName = $ServerName
        TestDate = Get-Date
        SessionId = $script:SessionId
        Version = $script:DiagnosticVersion
        Summary = @{}
        Details = @{}
        Warnings = @()
        Errors = @()
        OverallHealth = $false
        PerformanceMetrics = @{}
        Configuration = @{}
        SystemInfo = @{}
    }

    $result | Add-Member -MemberType ScriptMethod -Name AddTest -Value {
        param(
            [Parameter(Mandatory)]
            [string]$TestName,
            [Parameter(Mandatory)]
            [bool]$Success,
            [object]$Details = $null,
            [double]$DurationMs = 0,
            [string]$Category = 'General'
        )

        $this.Summary[$TestName] = $Success
        $this.Details[$TestName] = @{
            Success = $Success
            Details = $Details
            Category = $Category
            Timestamp = Get-Date
            Duration = $DurationMs
        }

        if ($DurationMs -gt 0) {
            $this.PerformanceMetrics[$TestName] = $DurationMs
        }

        # Calculate overall health based on critical tests
        $this.CalculateOverallHealth()
    }

    $result | Add-Member -MemberType ScriptMethod -Name AddWarning -Value {
        param([string]$Warning, [string]$Category = 'General')
        $this.Warnings += @{
            Message = $Warning
            Category = $Category
            Timestamp = Get-Date
        }
    }

    $result | Add-Member -MemberType ScriptMethod -Name AddError -Value {
        param([string]$Error, [string]$Category = 'General')
        $this.Errors += @{
            Message = $Error
            Category = $Category
            Timestamp = Get-Date
        }
    }

    $result | Add-Member -MemberType ScriptMethod -Name CalculateOverallHealth -Value {
        $criticalTests = @('DNS', 'Ping', 'CIM', 'Spooler')
        $criticalResults = $criticalTests | ForEach-Object {
            if ($this.Summary.ContainsKey($_)) {
                $this.Summary[$_]
            } else {
                $true  # If test not run, assume OK
            }
        }

        # Overall health is good if no critical failures and error count is acceptable
        $criticalFailures = ($criticalResults -contains $false)
        $excessiveErrors = $this.Errors.Count -gt 5

        $this.OverallHealth = -not ($criticalFailures -or $excessiveErrors)
    }

    $result | Add-Member -MemberType ScriptMethod -Name GetHealthScore -Value {
        $totalTests = $this.Summary.Count
        if ($totalTests -eq 0) { return 0 }

        $passedTests = ($this.Summary.Values | Where-Object { $_ -eq $true }).Count
        return [math]::Round(($passedTests / $totalTests) * 100, 1)
    }

    return $result
}

function New-ConfigurationManager {
    [CmdletBinding()]
    param(
        [string]$ConfigPath
    )

    $configManager = [PSCustomObject]@{
        PSTypeName = 'PrintServerDiagnostic.ConfigurationManager'
        ConfigPath = $ConfigPath
        Configuration = @{}
        DefaultConfiguration = @{
            version = "2.1.0"
            logging = @{
                level = "INFO"
                enableConsole = $true
                enableFile = $true
                rotateSize = 10MB
            }
            timeouts = @{
                general = 30
                ping = 5
                port = 5000
                cim = 30
                eventLog = 60
            }
            parallel = @{
                enabled = $true
                maxThreads = 10
                batchSize = 25
            }
            tests = @{
                network = @{
                    dnsResolution = $true
                    pingTest = $true
                    portScan = $true
                }
                system = @{
                    cimConnection = $true
                    serviceStatus = $true
                    eventLogs = $true
                }
                printing = @{
                    spoolerService = $true
                    printerEnumeration = $true
                    shareAccess = $true
                    spoolDirectory = $true
                }
            }
            reporting = @{
                autoOpen = $true
                includeCharts = $true
                formats = @("HTML", "JSON")
            }
        }
    }

    $configManager | Add-Member -MemberType ScriptMethod -Name LoadConfiguration -Value {
        if (Test-Path $this.ConfigPath) {
            try {
                $fileConfig = Get-Content $this.ConfigPath -Raw | ConvertFrom-Json
                $this.Configuration = $this.MergeConfiguration($this.DefaultConfiguration, $fileConfig)
                Write-Verbose "Configuration loaded from: $($this.ConfigPath)"
            }
            catch {
                Write-Warning "Failed to load configuration from $($this.ConfigPath): $($_.Exception.Message)"
                $this.Configuration = $this.DefaultConfiguration
            }
        }
        else {
            Write-Verbose "Configuration file not found, using defaults: $($this.ConfigPath)"
            $this.Configuration = $this.DefaultConfiguration
            $this.SaveConfiguration()
        }
    }

    $configManager | Add-Member -MemberType ScriptMethod -Name SaveConfiguration -Value {
        try {
            $configDir = Split-Path $this.ConfigPath -Parent
            if (-not (Test-Path $configDir)) {
                New-Item -Path $configDir -ItemType Directory -Force | Out-Null
            }
            $this.Configuration | ConvertTo-Json -Depth 10 | Out-File $this.ConfigPath -Encoding UTF8
            Write-Verbose "Configuration saved to: $($this.ConfigPath)"
        }
        catch {
            Write-Warning "Failed to save configuration: $($_.Exception.Message)"
        }
    }

    $configManager | Add-Member -MemberType ScriptMethod -Name MergeConfiguration -Value {
        param($Default, $Override)

        $merged = $Default.Clone()

        foreach ($key in $Override.PSObject.Properties.Name) {
            if ($merged.ContainsKey($key) -and $merged[$key] -is [hashtable] -and $Override.$key -is [PSCustomObject]) {
                $merged[$key] = $this.MergeConfiguration($merged[$key], $Override.$key)
            }
            else {
                $merged[$key] = $Override.$key
            }
        }

        return $merged
    }

    $configManager | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param([string]$Path, $DefaultValue = $null)

        $parts = $Path.Split('.')
        $current = $this.Configuration

        foreach ($part in $parts) {
            if ($current -is [hashtable] -and $current.ContainsKey($part)) {
                $current = $current[$part]
            }
            else {
                return $DefaultValue
            }
        }

        return $current
    }

    # Initialize configuration
    $configManager.LoadConfiguration()

    return $configManager
}

# =============================================================================
# DIAGNOSTIC FUNCTIONS WITH ENHANCED ERROR HANDLING
# =============================================================================

function Invoke-SafeOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Operation,

        [string]$OperationName = "Operation",

        [object]$Logger,

        [int]$MaxRetries = 3,

        [int]$DelaySeconds = 2,

        [string[]]$RetryableErrors = @('TimeoutException', 'NetworkException', 'COMException')
    )

    $attempt = 0
    $lastError = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    do {
        $attempt++
        try {
            $result = & $Operation
            $stopwatch.Stop()

            if ($Logger) {
                $Logger.WriteInfo("$OperationName completed successfully on attempt $attempt", @{
                    Duration = $stopwatch.ElapsedMilliseconds
                    Attempt = $attempt
                }, 'Operation')
            }

            return @{
                Success = $true
                Result = $result
                Duration = $stopwatch.ElapsedMilliseconds
                Attempts = $attempt
                Error = $null
            }
        }
        catch {
            $lastError = $_
            $errorMessage = $_.Exception.Message

            # Check if error is retryable
            $isRetryable = $RetryableErrors.Count -eq 0 -or ($RetryableErrors | Where-Object { $errorMessage -match $_ })

            if ($attempt -lt $MaxRetries -and $isRetryable) {
                if ($Logger) {
                    $Logger.WriteWarning("$OperationName failed on attempt $attempt, retrying in $DelaySeconds seconds", @{
                        Error = $errorMessage
                        Attempt = $attempt
                        Retryable = $isRetryable
                    }, 'Operation')
                }
                Start-Sleep -Seconds $DelaySeconds
                continue
            }
            else {
                $stopwatch.Stop()
                if ($Logger) {
                    $Logger.WriteError("$OperationName failed after $attempt attempts", @{
                        Error = $errorMessage
                        Duration = $stopwatch.ElapsedMilliseconds
                        FinalAttempt = $attempt
                        StackTrace = $_.ScriptStackTrace
                    }, 'Operation')
                }
                break
            }
        }
    } while ($attempt -lt $MaxRetries)

    return @{
        Success = $false
        Result = $null
        Duration = $stopwatch.ElapsedMilliseconds
        Attempts = $attempt
        Error = $lastError.Exception.Message
        Exception = $lastError
    }
}

function Test-NetworkConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [int]$Count = 2,
        [int]$TimeoutSeconds = 5,
        [object]$Logger,
        [object]$Config
    )

    $operation = {
        $Logger.WriteInfo("Testing network connectivity to $ComputerName", $null, 'Network')

        # Enhanced ping with IPv4/IPv6 support
        $pingResults = @()
        for ($i = 1; $i -le $Count; $i++) {
            try {
                $ping = Test-Connection -ComputerName $ComputerName -Count 1 -TimeoutSeconds $TimeoutSeconds -ErrorAction Stop
                $pingResults += $ping
            }
            catch {
                $pingResults += [PSCustomObject]@{
                    Status = 'TimedOut'
                    ResponseTime = $null
                    Address = $ComputerName
                }
            }
        }

        $successfulPings = $pingResults | Where-Object { $_.Status -eq 'Success' }
        $isSuccessful = $successfulPings.Count -gt 0

        $analysis = @{
            SuccessfulPings = $successfulPings.Count
            TotalPings = $Count
            SuccessRate = [math]::Round(($successfulPings.Count / $Count) * 100, 1)
            AverageResponseTime = if ($successfulPings.Count -gt 0) {
                [math]::Round(($successfulPings | Measure-Object ResponseTime -Average).Average, 2)
            } else { $null }
            MinResponseTime = if ($successfulPings.Count -gt 0) {
                ($successfulPings | Measure-Object ResponseTime -Minimum).Minimum
            } else { $null }
            MaxResponseTime = if ($successfulPings.Count -gt 0) {
                ($successfulPings | Measure-Object ResponseTime -Maximum).Maximum
            } else { $null }
            Results = $pingResults
        }

        return @{
            IsSuccessful = $isSuccessful
            Analysis = $analysis
            RawResults = $pingResults
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "NetworkConnectivity-$ComputerName" -Logger $Logger -MaxRetries 2
}

function Test-TcpPortsParallel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [Parameter(Mandatory)]
        [int[]]$Ports,
        [int]$TimeoutMs = 5000,
        [int]$ThrottleLimit = 10,
        [object]$Logger,
        [switch]$UseRunspacePool
    )

    $operation = {
        $Logger.WriteInfo("Starting parallel port scan of $($Ports.Count) ports on $ComputerName", @{
            Ports = $Ports -join ','
            ThrottleLimit = $ThrottleLimit
            TimeoutMs = $TimeoutMs
        }, 'Network')

        if ($UseRunspacePool -and $PSVersionTable.PSVersion.Major -ge 7) {
            # Use runspace pool for better performance in PowerShell 7+
            $portResults = Test-PortsWithRunspacePool -ComputerName $ComputerName -Ports $Ports -TimeoutMs $TimeoutMs -ThrottleLimit $ThrottleLimit
        }
        else {
            # Use ForEach-Object -Parallel for PowerShell 7+ or fallback for 5.1
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $portResults = $Ports | ForEach-Object -Parallel {
                    $port = $_
                    $computer = $using:ComputerName
                    $timeout = $using:TimeoutMs

                    $portTest = @{
                        Port = $port
                        IsOpen = $false
                        ResponseTime = $null
                        Status = 'Unknown'
                        Error = $null
                    }

                    try {
                        $tcpClient = [System.Net.Sockets.TcpClient]::new()
                        $connectTask = $tcpClient.ConnectAsync($computer, $port)
                        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                        if ($connectTask.Wait($timeout)) {
                            $stopwatch.Stop()
                            $portTest.IsOpen = $tcpClient.Connected
                            $portTest.ResponseTime = $stopwatch.ElapsedMilliseconds
                            $portTest.Status = if ($tcpClient.Connected) { 'Open' } else { 'Closed' }
                        }
                        else {
                            $stopwatch.Stop()
                            $portTest.Status = 'Timeout'
                            $portTest.ResponseTime = $timeout
                        }

                        $tcpClient.Close()
                        $tcpClient.Dispose()
                    }
                    catch {
                        $portTest.Status = 'Error'
                        $portTest.Error = $_.Exception.Message
                    }

                    return [PSCustomObject]$portTest
                } -ThrottleLimit $ThrottleLimit
            }
            else {
                # PowerShell 5.1 fallback - sequential with jobs
                $portResults = Test-PortsWithJobs -ComputerName $ComputerName -Ports $Ports -TimeoutMs $TimeoutMs -ThrottleLimit $ThrottleLimit
            }
        }

        $openPorts = ($portResults | Where-Object IsOpen).Count
        $closedPorts = ($portResults | Where-Object { $_.Status -eq 'Closed' }).Count
        $timeoutPorts = ($portResults | Where-Object { $_.Status -eq 'Timeout' }).Count
        $errorPorts = ($portResults | Where-Object { $_.Status -eq 'Error' }).Count

        $analysis = @{
            TotalPorts = $Ports.Count
            OpenPorts = $openPorts
            ClosedPorts = $closedPorts
            TimeoutPorts = $timeoutPorts
            ErrorPorts = $errorPorts
            SuccessRate = [math]::Round(($openPorts / $Ports.Count) * 100, 1)
            AverageResponseTime = if ($openPorts -gt 0) {
                $openPortResults = $portResults | Where-Object IsOpen
                [math]::Round(($openPortResults | Measure-Object ResponseTime -Average).Average, 2)
            } else { $null }
        }

        $Logger.WriteInfo("Port scan completed", $analysis, 'Network')

        return @{
            IsSuccessful = $openPorts -gt 0
            Analysis = $analysis
            Results = $portResults
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "PortScan-$ComputerName" -Logger $Logger
}

function Test-PortsWithJobs {
    param($ComputerName, $Ports, $TimeoutMs, $ThrottleLimit)

    $jobs = @()
    $results = @()

    # Create jobs in batches to respect throttle limit
    for ($i = 0; $i -lt $Ports.Count; $i += $ThrottleLimit) {
        $batch = $Ports[$i..($i + $ThrottleLimit - 1)]

        foreach ($port in $batch) {
            $job = Start-Job -ScriptBlock {
                param($Computer, $Port, $Timeout)

                $result = @{
                    Port = $Port
                    IsOpen = $false
                    ResponseTime = $null
                    Status = 'Unknown'
                    Error = $null
                }

                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $asyncResult = $tcpClient.BeginConnect($Computer, $Port, $null, $null)
                    $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)
                    $stopwatch.Stop()

                    if ($wait) {
                        $tcpClient.EndConnect($asyncResult)
                        $result.IsOpen = $true
                        $result.Status = 'Open'
                        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
                    }
                    else {
                        $result.Status = 'Timeout'
                        $result.ResponseTime = $Timeout
                    }

                    $tcpClient.Close()
                }
                catch {
                    $result.Status = 'Error'
                    $result.Error = $_.Exception.Message
                }

                return [PSCustomObject]$result
            } -ArgumentList $ComputerName, $port, $TimeoutMs

            $jobs += $job
        }

        # Wait for current batch to complete before starting next batch
        if (($jobs.Count -ge $ThrottleLimit) -or ($i + $ThrottleLimit -ge $Ports.Count)) {
            $batchResults = $jobs | Wait-Job | Receive-Job
            $results += $batchResults
            $jobs | Remove-Job
            $jobs = @()
        }
    }

    return $results
}

function New-SecureCimSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [PSCredential]$Credential,
        [int]$TimeoutSeconds = 30,
        [object]$Logger,
        [string[]]$ProtocolPreference = @('Dcom', 'WSMan')
    )

    $operation = {
        $Logger.WriteInfo("Attempting to create secure CIM session to $ComputerName", @{
            ProtocolPreference = $ProtocolPreference -join ','
            TimeoutSeconds = $TimeoutSeconds
        }, 'CIM')

        $session = $null
        $protocol = $null
        $lastError = $null

        foreach ($preferredProtocol in $ProtocolPreference) {
            try {
                $Logger.WriteDebug("Trying $preferredProtocol protocol for $ComputerName", $null, 'CIM')

                $sessionOption = New-CimSessionOption -Protocol $preferredProtocol
                $sessionParams = @{
                    ComputerName = $ComputerName
                    SessionOption = $sessionOption
                    ErrorAction = 'Stop'
                }

                if ($Credential) {
                    $sessionParams.Credential = $Credential
                    $Logger.WriteDebug("Using provided credentials for CIM session", $null, 'CIM')
                }

                $session = New-CimSession @sessionParams
                $protocol = $preferredProtocol

                # Test the session
                $null = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop

                $Logger.WriteInfo("CIM session established successfully via $protocol", $null, 'CIM')
                break
            }
            catch {
                $lastError = $_
                $Logger.WriteWarning("Failed to establish CIM session via $preferredProtocol", @{
                    Error = $_.Exception.Message
                    Protocol = $preferredProtocol
                }, 'CIM')

                if ($session) {
                    Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue
                    $session = $null
                }
                continue
            }
        }

        if (-not $session) {
            throw "Failed to establish CIM session using any preferred protocol: $($lastError.Exception.Message)"
        }

        return @{
            Session = $session
            Protocol = $protocol
            ComputerName = $ComputerName
            EstablishedAt = Get-Date
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "CimSession-$ComputerName" -Logger $Logger -MaxRetries 2
}

function Test-PrintServerServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [object]$Logger,
        [string[]]$ServiceNames = @('Spooler', 'PrintNotify', 'PrintWorkflowUserSvc')
    )

    $operation = {
        $Logger.WriteInfo("Testing print server services on $ComputerName", @{
            Services = $ServiceNames -join ','
            HasCimSession = ($null -ne $CimSession)
        }, 'PrintServices')

        $serviceResults = @{}
        $allServicesHealthy = $true
        $useCim = ($null -ne $CimSession)

        foreach ($serviceName in $ServiceNames) {
            try {
                $service = $null
                $serviceInfo = $null

                if ($useCim) {
                    # Try CIM first for detailed information
                    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -CimSession $CimSession -ErrorAction Stop

                    if ($service) {
                        $serviceInfo = [PSCustomObject]@{
                            Name = $service.Name
                            DisplayName = $service.DisplayName
                            State = $service.State
                            StartMode = $service.StartMode
                            Status = $service.Status
                            ProcessId = $service.ProcessId
                            PathName = $service.PathName
                            Started = $service.Started
                            AcceptStop = $service.AcceptStop
                            AcceptPause = $service.AcceptPause
                            Method = 'CIM'
                        }
                    }
                }
                else {
                    # Fallback to Get-Service for basic information when targeting localhost or accessible remote
                    if ($ComputerName -eq 'localhost' -or $ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq '127.0.0.1') {
                        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    }
                    else {
                        # For remote computers without CIM, try remote registry or alternative methods
                        try {
                            $service = Get-Service -ComputerName $ComputerName -Name $serviceName -ErrorAction SilentlyContinue
                        }
                        catch {
                            $Logger.WriteDebug("Remote service query failed, trying alternative method", @{
                                Service = $serviceName
                                Computer = $ComputerName
                                Error = $_.Exception.Message
                            }, 'PrintServices')
                        }
                    }

                    if ($service) {
                        $serviceInfo = [PSCustomObject]@{
                            Name = $service.Name
                            DisplayName = $service.DisplayName
                            State = $service.Status.ToString()
                            StartMode = $service.StartType.ToString()
                            Status = if ($service.Status -eq 'Running') { 'OK' } else { 'Unknown' }
                            ProcessId = 0  # Not available via Get-Service
                            PathName = 'N/A'
                            Started = ($service.Status -eq 'Running')
                            AcceptStop = $service.CanStop
                            AcceptPause = $service.CanPauseAndContinue
                            Method = 'Service'
                        }
                    }
                }

                if ($service) {
                    $isHealthy = ($serviceInfo.State -eq 'Running' -and ($serviceInfo.Status -eq 'OK' -or $serviceInfo.Status -eq 'Unknown'))
                    if (-not $isHealthy -and $serviceName -eq 'Spooler') {
                        $allServicesHealthy = $false  # Spooler is critical
                    }

                    $serviceResults[$serviceName] = @{
                        Found = $true
                        Healthy = $isHealthy
                        ServiceInfo = $serviceInfo
                        Critical = ($serviceName -eq 'Spooler')
                    }

                    $Logger.WriteInfo("Service $serviceName status: $($serviceInfo.State)", @{
                        Service = $serviceName
                        State = $serviceInfo.State
                        Method = $serviceInfo.Method
                    }, 'PrintServices')
                }
                else {
                    $serviceResults[$serviceName] = @{
                        Found = $false
                        Healthy = $false
                        ServiceInfo = $null
                        Critical = ($serviceName -eq 'Spooler')
                        Error = "Service not found or inaccessible"
                    }

                    if ($serviceName -eq 'Spooler') {
                        $allServicesHealthy = $false
                    }

                    $Logger.WriteWarning("Service $serviceName not found on $ComputerName", @{
                        Method = if ($useCim) { 'CIM' } else { 'Service' }
                    }, 'PrintServices')
                }
            }
            catch {
                $serviceResults[$serviceName] = @{
                    Found = $false
                    Healthy = $false
                    ServiceInfo = $null
                    Critical = ($serviceName -eq 'Spooler')
                    Error = $_.Exception.Message
                }

                if ($serviceName -eq 'Spooler') {
                    $allServicesHealthy = $false
                }

                $Logger.WriteError("Failed to query service $serviceName on $ComputerName", @{
                    Service = $serviceName
                    Error = $_.Exception.Message
                    Method = if ($useCim) { 'CIM' } else { 'Service' }
                }, 'PrintServices')
            }
        }

        $analysis = @{
            TotalServices = $ServiceNames.Count
            HealthyServices = ($serviceResults.Values | Where-Object { $_.Healthy }).Count
            CriticalServicesHealthy = ($serviceResults.Values | Where-Object { $_.Critical -and $_.Healthy }).Count
            CriticalServicesTotal = ($serviceResults.Values | Where-Object { $_.Critical }).Count
            AllServicesHealthy = $allServicesHealthy
        }

        return @{
            IsSuccessful = $allServicesHealthy
            Analysis = $analysis
            Services = $serviceResults
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "PrintServices-$ComputerName" -Logger $Logger
}

function Test-PrintServerShares {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Testing print server shares on $ComputerName", $null, 'PrintShares')

        $shareResults = @{
            CimAvailable = $null -ne $CimSession
            SharesFound = @()
            PrintShareAccessible = $false
            DriverShareAccessible = $false
            Analysis = @{}
        }

        # Test using CIM if available
        if ($CimSession) {
            try {
                $shares = Get-CimInstance -ClassName Win32_Share -CimSession $CimSession |
                         Where-Object { $_.Name -in @("print$", "Printers") -or $_.Type -eq 1 }

                $shareResults.SharesFound = $shares | ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.Name
                        Path = $_.Path
                        Description = $_.Description
                        Type = $_.Type
                        MaximumAllowed = $_.MaximumAllowed
                        AllowMaximum = $_.AllowMaximum
                    }
                }

                $Logger.WriteInfo("Found $($shares.Count) print-related shares via CIM", @{
                    Shares = ($shares | Select-Object Name, Path)
                }, 'PrintShares')
            }
            catch {
                $Logger.WriteWarning("Could not enumerate shares via CIM: $($_.Exception.Message)", $null, 'PrintShares')
            }
        }

        # Test direct share access
        $printSharePath = "\\$ComputerName\print$"
        try {
            $shareResults.PrintShareAccessible = Test-Path $printSharePath -ErrorAction Stop
            $Logger.WriteInfo("Print share (print$) accessibility test", @{
                Path = $printSharePath
                Accessible = $shareResults.PrintShareAccessible
            }, 'PrintShares')
        }
        catch {
            $shareResults.PrintShareAccessible = $false
            $Logger.WriteWarning("Cannot access print share", @{
                Path = $printSharePath
                Error = $_.Exception.Message
            }, 'PrintShares')
        }

        # Check driver share if print$ is accessible
        if ($shareResults.PrintShareAccessible) {
            try {
                $driverPath = "$printSharePath\drivers"
                $shareResults.DriverShareAccessible = Test-Path $driverPath -ErrorAction SilentlyContinue
            }
            catch {
                $shareResults.DriverShareAccessible = $false
            }
        }

        $shareResults.Analysis = @{
            SharesFoundCount = $shareResults.SharesFound.Count
            PrintShareWorking = $shareResults.PrintShareAccessible
            DriverShareWorking = $shareResults.DriverShareAccessible
            OverallShareHealth = $shareResults.PrintShareAccessible
        }

        return @{
            IsSuccessful = $shareResults.PrintShareAccessible
            Analysis = $shareResults.Analysis
            Details = $shareResults
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "PrintShares-$ComputerName" -Logger $Logger
}

function Get-PrintServerPrinters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [Parameter(Mandatory)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Enumerating printers on $ComputerName", $null, 'Printers')

        $printers = Get-CimInstance -ClassName Win32_Printer -CimSession $CimSession -ErrorAction Stop

        $printerAnalysis = $printers | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                ShareName = $_.ShareName
                SystemName = $_.SystemName
                WorkOffline = $_.WorkOffline
                PrinterStatus = $_.PrinterStatus
                Default = $_.Default
                Network = $_.Network
                Shared = $_.Shared
                DriverName = $_.DriverName
                PortName = $_.PortName
                Location = $_.Location
                Comment = $_.Comment
                Status = switch ($_.PrinterStatus) {
                    1 { 'Other' }
                    2 { 'Unknown' }
                    3 { 'Idle' }
                    4 { 'Printing' }
                    5 { 'Warmup' }
                    6 { 'Stopped Printing' }
                    7 { 'Offline' }
                    default { 'Unknown' }
                }
                IsHealthy = (-not $_.WorkOffline -and $_.PrinterStatus -in @(1,3,4,5))
            }
        }

        $statistics = @{
            TotalPrinters = $printers.Count
            SharedPrinters = ($printerAnalysis | Where-Object Shared).Count
            NetworkPrinters = ($printerAnalysis | Where-Object Network).Count
            OfflinePrinters = ($printerAnalysis | Where-Object WorkOffline).Count
            HealthyPrinters = ($printerAnalysis | Where-Object IsHealthy).Count
            DefaultPrinter = ($printerAnalysis | Where-Object Default | Select-Object -First 1 -ExpandProperty Name -ErrorAction SilentlyContinue)
        }

        $Logger.WriteInfo("Printer enumeration completed", $statistics, 'Printers')

        return @{
            IsSuccessful = $printers.Count -gt 0
            Analysis = $statistics
            Printers = $printerAnalysis
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "PrinterEnum-$ComputerName" -Logger $Logger
}

function Get-ClientSidePrinters {
    <#
    .SYNOPSIS
        Enumerates printers accessible to the current user without requiring elevation
    .DESCRIPTION
        Uses standard user-accessible cmdlets to enumerate local and network printers
        without requiring administrative privileges
    #>
    [CmdletBinding()]
    param(
        [object]$Logger,
        [switch]$IncludeDetailedInfo
    )

    $operation = {
        $Logger.WriteInfo("Enumerating client-side accessible printers", $null, 'ClientPrinters')

        $printers = @()
        $errorSuggestions = @()

        try {
            # Use Get-Printer which works with standard user permissions for local and network printers
            if (Get-Command Get-Printer -ErrorAction SilentlyContinue) {
                $allPrinters = Get-Printer -ErrorAction SilentlyContinue

                foreach ($printer in $allPrinters) {
                    $printerDetails = [PSCustomObject]@{
                        Name = $printer.Name
                        ComputerName = $printer.ComputerName
                        Type = $printer.Type
                        DriverName = $printer.DriverName
                        PortName = $printer.PortName
                        Location = $printer.Location
                        Comment = $printer.Comment
                        Shared = $printer.Shared
                        Published = $printer.Published
                        PrinterStatus = $printer.PrinterStatus
                        DeviceType = $printer.DeviceType
                        WorkflowPolicy = $printer.WorkflowPolicy
                        IsDefault = $false
                        ConnectivityTest = @{}
                        DetailedInfo = @{}
                        PortInfo = @{}
                        ErrorSuggestions = @()
                    }

                    # Check if this is the default printer
                    try {
                        $defaultPrinter = Get-CimInstance -ClassName Win32_Printer -Filter "Default=TRUE" -ErrorAction SilentlyContinue
                        if ($defaultPrinter -and $defaultPrinter.Name -eq $printer.Name) {
                            $printerDetails.IsDefault = $true
                        }
                    }
                    catch {
                        # Fallback to registry check
                        try {
                            $defaultPrinterName = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "Device" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Device
                            if ($defaultPrinterName -and $defaultPrinterName.StartsWith($printer.Name)) {
                                $printerDetails.IsDefault = $true
                            }
                        }
                        catch { }
                    }

                    # Test printer connectivity
                    $printerDetails.ConnectivityTest = Test-ClientPrinterConnectivity -PrinterName $printer.Name -Logger $Logger

                    # Get detailed printer information if requested
                    if ($IncludeDetailedInfo) {
                        $printerDetails.DetailedInfo = Get-DetailedPrinterInfo -PrinterName $printer.Name -Logger $Logger
                        $printerDetails.PortInfo = Get-PrinterPortInfo -PortName $printer.PortName -Logger $Logger
                    }

                    # Generate error suggestions based on printer status
                    $printerDetails.ErrorSuggestions = Get-PrinterErrorSuggestions -Printer $printer -Logger $Logger

                    $printers += $printerDetails
                }
            } else {
                $Logger.WriteWarning("Get-Printer cmdlet not available, falling back to WMI", $null, 'ClientPrinters')

                # Fallback to WMI with current user context
                $wmiPrinters = Get-WmiObject -Class Win32_Printer -ErrorAction SilentlyContinue
                foreach ($printer in $wmiPrinters) {
                    $printerDetails = [PSCustomObject]@{
                        Name = $printer.Name
                        ComputerName = $printer.SystemName
                        Type = 'Unknown'
                        DriverName = $printer.DriverName
                        PortName = $printer.PortName
                        Location = $printer.Location
                        Comment = $printer.Comment
                        Shared = $printer.Shared
                        Published = $false
                        PrinterStatus = $printer.PrinterStatus
                        DeviceType = $printer.DeviceType
                        WorkflowPolicy = 'Unknown'
                        IsDefault = $printer.Default
                        ConnectivityTest = @{}
                        DetailedInfo = @{}
                        PortInfo = @{}
                        ErrorSuggestions = @()
                    }

                    $printers += $printerDetails
                }
            }
        }
        catch {
            $Logger.WriteError("Failed to enumerate printers: $($_.Exception.Message)", $null, 'ClientPrinters')
            $errorSuggestions += "Unable to enumerate printers. Try running as administrator or check printer services."
        }

        # Get network printer connections
        try {
            $networkPrinters = Get-ChildItem -Path "HKCU:\Printers\Connections" -ErrorAction SilentlyContinue | ForEach-Object {
                $printerPath = $_.PSChildName
                [PSCustomObject]@{
                    Name = $printerPath.Replace(",,", "\")
                    Type = "Network"
                    IsNetworkConnection = $true
                    RegistryPath = $_.Name
                }
            }

            foreach ($netPrinter in $networkPrinters) {
                if ($printers.Name -notcontains $netPrinter.Name) {
                    $printers += $netPrinter
                }
            }
        }
        catch {
            $Logger.WriteWarning("Could not enumerate network printer connections from registry", $null, 'ClientPrinters')
        }

        $statistics = @{
            TotalPrinters = $printers.Count
            LocalPrinters = ($printers | Where-Object { $_.Type -eq 'Local' -or $_.ComputerName -eq $env:COMPUTERNAME }).Count
            NetworkPrinters = ($printers | Where-Object { $_.Type -eq 'Connection' -or $_.IsNetworkConnection }).Count
            DefaultPrinter = ($printers | Where-Object IsDefault | Select-Object -First 1 -ExpandProperty Name)
            SharedPrinters = ($printers | Where-Object Shared).Count
            PrintersWithIssues = ($printers | Where-Object { $_.ErrorSuggestions.Count -gt 0 }).Count
        }

        $Logger.WriteInfo("Client-side printer enumeration completed", $statistics, 'ClientPrinters')

        return @{
            IsSuccessful = $printers.Count -gt 0
            Analysis = $statistics
            Printers = $printers
            ErrorSuggestions = $errorSuggestions
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "ClientPrinterEnum" -Logger $Logger
}

function Test-ClientPrinterConnectivity {
    <#
    .SYNOPSIS
        Tests printer connectivity using client-side methods
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PrinterName,
        [object]$Logger
    )

    $connectivityTest = @{
        CanPrint = $false
        TestJobSent = $false
        ResponseTime = 0
        LastError = $null
        TestMethod = 'Unknown'
    }

    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        # Try to send a test page (requires user interaction, so we'll skip)
        # Instead, we'll check if the printer responds to basic queries

        if (Get-Command Get-PrinterProperties -ErrorAction SilentlyContinue) {
            $properties = Get-PrinterProperties -PrinterName $PrinterName -ErrorAction SilentlyContinue
            if ($properties) {
                $connectivityTest.CanPrint = $true
                $connectivityTest.TestMethod = 'Get-PrinterProperties'
            }
        }

        # Alternative method using .NET PrinterSettings
        try {
            $printerSettings = New-Object System.Drawing.Printing.PrinterSettings
            $printerSettings.PrinterName = $PrinterName
            if ($printerSettings.IsValid) {
                $connectivityTest.CanPrint = $true
                $connectivityTest.TestMethod = 'PrinterSettings'
            }
        }
        catch {
            # PrinterSettings not available in all environments
        }

        $stopwatch.Stop()
        $connectivityTest.ResponseTime = $stopwatch.ElapsedMilliseconds

    }
    catch {
        $connectivityTest.LastError = $_.Exception.Message
        $Logger.WriteWarning("Printer connectivity test failed for $PrinterName`: $($_.Exception.Message)", $null, 'ClientPrinters')
    }

    return $connectivityTest
}

function Get-DetailedPrinterInfo {
    <#
    .SYNOPSIS
        Retrieves detailed printer information including firmware and capabilities
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PrinterName,
        [object]$Logger
    )

    $detailedInfo = @{
        Capabilities = @()
        PaperSizes = @()
        ColorCapability = 'Unknown'
        DuplexCapability = 'Unknown'
        MaxResolution = 'Unknown'
        FirmwareVersion = 'Unknown'
        SerialNumber = 'Unknown'
        ModelNumber = 'Unknown'
        PageCount = 'Unknown'
        TonerLevels = @()
        ErrorState = 'Unknown'
        StatusInfo = @{}
    }

    try {
        # Try to get detailed printer configuration
        if (Get-Command Get-PrintConfiguration -ErrorAction SilentlyContinue) {
            $config = Get-PrintConfiguration -PrinterName $PrinterName -ErrorAction SilentlyContinue
            if ($config) {
                $detailedInfo.ColorCapability = if ($config.Color) { 'Color' } else { 'Monochrome' }
                $detailedInfo.DuplexCapability = if ($config.DuplexingMode -ne 'OneSided') { 'Duplex' } else { 'Simplex' }
            }
        }

        # Try to get printer properties for more details
        if (Get-Command Get-PrinterProperty -ErrorAction SilentlyContinue) {
            $properties = Get-PrinterProperty -PrinterName $PrinterName -ErrorAction SilentlyContinue
            foreach ($prop in $properties) {
                switch ($prop.PropertyName) {
                    'Config:Model' { $detailedInfo.ModelNumber = $prop.Value }
                    'Config:SerialNumber' { $detailedInfo.SerialNumber = $prop.Value }
                    'Config:FirmwareVersion' { $detailedInfo.FirmwareVersion = $prop.Value }
                    'Status:PageCount' { $detailedInfo.PageCount = $prop.Value }
                    'Status:TonerLevel' {
                        $detailedInfo.TonerLevels += @{
                            Color = 'Unknown'
                            Level = $prop.Value
                        }
                    }
                }
            }
        }

        # Try SNMP queries for network printers (if port suggests network printer)
        $printerObj = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        if ($printerObj -and $printerObj.PortName -match '^IP_|^WSD_|^TCP') {
            $detailedInfo = Get-SNMPPrinterInfo -PrinterName $PrinterName -PortName $printerObj.PortName -DetailedInfo $detailedInfo -Logger $Logger
        }

    }
    catch {
        $Logger.WriteWarning("Could not retrieve detailed info for printer $PrinterName`: $($_.Exception.Message)", $null, 'DetailedInfo')
    }

    return $detailedInfo
}

function Get-SNMPPrinterInfo {
    <#
    .SYNOPSIS
        Attempts to retrieve printer information via SNMP queries
    #>
    [CmdletBinding()]
    param(
        [string]$PrinterName,
        [string]$PortName,
        [hashtable]$DetailedInfo,
        [object]$Logger
    )

    try {
        # Extract IP address from port name
        $ipAddress = $null
        if ($PortName -match 'IP_(\d+\.\d+\.\d+\.\d+)') {
            $ipAddress = $matches[1]
        }
        elseif ($PortName -match 'TCP_(\d+\.\d+\.\d+\.\d+)') {
            $ipAddress = $matches[1]
        }

        if ($ipAddress) {
            $Logger.WriteInfo("Attempting SNMP queries for printer at $ipAddress", $null, 'SNMP')

            # Common SNMP OIDs for printer information
            $snmpOids = @{
                'Model' = '1.3.6.1.2.1.25.3.2.1.3.1'
                'SerialNumber' = '1.3.6.1.2.1.43.5.1.1.17.1'
                'FirmwareVersion' = '1.3.6.1.2.1.25.3.2.1.4.1'
                'PageCount' = '1.3.6.1.2.1.43.10.2.1.4.1.1'
                'DeviceStatus' = '1.3.6.1.2.1.25.3.2.1.5.1'
            }

            # Note: SNMP queries would require additional modules/tools
            # This is a framework for SNMP integration
            $DetailedInfo.StatusInfo.SNMPAttempted = $true
            $DetailedInfo.StatusInfo.IPAddress = $ipAddress
        }
    }
    catch {
        $Logger.WriteWarning("SNMP query failed: $($_.Exception.Message)", $null, 'SNMP')
    }

    return $DetailedInfo
}

function Get-PrinterPortInfo {
    <#
    .SYNOPSIS
        Provides detailed information about printer ports and their purposes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PortName,
        [object]$Logger
    )

    $portInfo = @{
        PortName = $PortName
        PortType = 'Unknown'
        Protocol = 'Unknown'
        Description = 'Unknown port type'
        CommonUse = 'Unknown'
        TroubleshootingTips = @()
        IsNetworkPort = $false
        ConnectionDetails = @{}
    }

    # Analyze port name to determine type and provide information
    switch -Regex ($PortName) {
        '^LPT\d+:$' {
            $portInfo.PortType = 'Parallel'
            $portInfo.Protocol = 'IEEE 1284'
            $portInfo.Description = 'Legacy parallel port connection'
            $portInfo.CommonUse = 'Direct connection to local parallel port'
            $portInfo.TroubleshootingTips += 'Check physical cable connections'
            $portInfo.TroubleshootingTips += 'Verify printer is powered on'
            $portInfo.TroubleshootingTips += 'Try different parallel cable'
        }
        '^COM\d+:$' {
            $portInfo.PortType = 'Serial'
            $portInfo.Protocol = 'RS-232'
            $portInfo.Description = 'Serial port connection'
            $portInfo.CommonUse = 'Direct connection to local serial port'
            $portInfo.TroubleshootingTips += 'Check baud rate settings'
            $portInfo.TroubleshootingTips += 'Verify cable and connector type'
            $portInfo.TroubleshootingTips += 'Check flow control settings'
        }
        '^USB\d+' {
            $portInfo.PortType = 'USB'
            $portInfo.Protocol = 'USB'
            $portInfo.Description = 'USB connection'
            $portInfo.CommonUse = 'Direct USB connection to local printer'
            $portInfo.TroubleshootingTips += 'Try different USB port'
            $portInfo.TroubleshootingTips += 'Check USB cable integrity'
            $portInfo.TroubleshootingTips += 'Update or reinstall USB drivers'
        }
        '^IP_' {
            $portInfo.PortType = 'Standard TCP/IP'
            $portInfo.Protocol = 'TCP/IP (Raw or LPR)'
            $portInfo.Description = 'Network printer using Standard TCP/IP port'
            $portInfo.CommonUse = 'Network printers with direct IP connection'
            $portInfo.IsNetworkPort = $true

            if ($PortName -match 'IP_(\d+\.\d+\.\d+\.\d+)') {
                $portInfo.ConnectionDetails.IPAddress = $matches[1]
                $portInfo.ConnectionDetails.DefaultPort = '9100 (Raw) or 515 (LPR)'
            }

            $portInfo.TroubleshootingTips += 'Verify IP address is correct and reachable'
            $portInfo.TroubleshootingTips += 'Check firewall settings on both client and printer'
            $portInfo.TroubleshootingTips += 'Test connectivity with ping or telnet'
            $portInfo.TroubleshootingTips += 'Verify printer supports Raw printing on port 9100'
        }
        '^WSD-' {
            $portInfo.PortType = 'Web Services on Devices'
            $portInfo.Protocol = 'WS-Discovery/WSD'
            $portInfo.Description = 'Web Services for Devices port'
            $portInfo.CommonUse = 'Auto-discovered network printers using WSD protocol'
            $portInfo.IsNetworkPort = $true
            $portInfo.TroubleshootingTips += 'Check if WSD service is running on the printer'
            $portInfo.TroubleshootingTips += 'Verify network discovery is enabled'
            $portInfo.TroubleshootingTips += 'Try removing and re-adding the printer'
            $portInfo.TroubleshootingTips += 'Check Windows firewall WSD exceptions'
        }
        '^\\\\.+\\.+' {
            $portInfo.PortType = 'Network Share'
            $portInfo.Protocol = 'SMB/CIFS'
            $portInfo.Description = 'Shared printer on network computer'
            $portInfo.CommonUse = 'Printers shared from other Windows computers'
            $portInfo.IsNetworkPort = $true

            if ($PortName -match '\\\\([^\\]+)\\(.+)') {
                $portInfo.ConnectionDetails.ServerName = $matches[1]
                $portInfo.ConnectionDetails.ShareName = $matches[2]
            }

            $portInfo.TroubleshootingTips += 'Verify the print server is online and accessible'
            $portInfo.TroubleshootingTips += 'Check credentials for accessing the shared printer'
            $portInfo.TroubleshootingTips += 'Test SMB connectivity to the print server'
            $portInfo.TroubleshootingTips += 'Check print spooler service on print server'
        }
        '^FILE:$' {
            $portInfo.PortType = 'File'
            $portInfo.Protocol = 'File System'
            $portInfo.Description = 'Output to file instead of physical printer'
            $portInfo.CommonUse = 'Print-to-file functionality for creating print files'
            $portInfo.TroubleshootingTips += 'Verify file path and permissions'
            $portInfo.TroubleshootingTips += 'Check available disk space'
        }
        '^PORTPROMPT:$' {
            $portInfo.PortType = 'Port Prompt'
            $portInfo.Protocol = 'Variable'
            $portInfo.Description = 'Prompts user to select port at print time'
            $portInfo.CommonUse = 'Flexible port selection for different output methods'
            $portInfo.TroubleshootingTips += 'Ensure target ports are available when printing'
        }
        default {
            $portInfo.PortType = 'Custom/Unknown'
            $portInfo.Description = 'Custom or vendor-specific port type'
            $portInfo.CommonUse = 'Vendor-specific or custom printer port'
            $portInfo.TroubleshootingTips += 'Check vendor documentation for port type'
            $portInfo.TroubleshootingTips += 'Verify vendor-specific drivers are installed'
            $portInfo.TroubleshootingTips += 'Contact printer manufacturer for support'
        }
    }

    # Get additional port information if available
    try {
        if (Get-Command Get-PrinterPort -ErrorAction SilentlyContinue) {
            $port = Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue
            if ($port) {
                $portInfo.ConnectionDetails.PortMonitor = $port.PortMonitor
                $portInfo.ConnectionDetails.Description = $port.Description

                if ($port.PSObject.Properties.Name -contains 'PrinterHostAddress') {
                    $portInfo.ConnectionDetails.HostAddress = $port.PrinterHostAddress
                }
                if ($port.PSObject.Properties.Name -contains 'PortNumber') {
                    $portInfo.ConnectionDetails.PortNumber = $port.PortNumber
                }
            }
        }
    }
    catch {
        $Logger.WriteWarning("Could not retrieve additional port information for $PortName", $null, 'PortInfo')
    }

    return $portInfo
}

function Get-PrinterErrorSuggestions {
    <#
    .SYNOPSIS
        Generates helpful error suggestions based on printer status and common issues
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Printer,
        [object]$Logger
    )

    $suggestions = @()

    # Analyze printer status
    if ($Printer.PrinterStatus) {
        switch ($Printer.PrinterStatus) {
            2 { # Unknown
                $suggestions += "Printer status is unknown. Check if printer is properly connected and powered on."
                $suggestions += "Verify printer drivers are correctly installed."
            }
            6 { # Stopped Printing
                $suggestions += "Printer has stopped printing. Check for paper jams, empty paper trays, or toner issues."
                $suggestions += "Try restarting the print spooler service."
                $suggestions += "Clear any pending print jobs that might be causing issues."
            }
            7 { # Offline
                $suggestions += "Printer is offline. Check physical connections and power status."
                $suggestions += "For network printers, verify IP address and network connectivity."
                $suggestions += "Try setting the printer to online mode manually."
            }
        }
    }

    # Network printer specific suggestions
    if ($Printer.PortName -and ($Printer.PortName.StartsWith('IP_') -or $Printer.PortName.StartsWith('WSD-'))) {
        $suggestions += "For network connectivity issues:"
        $suggestions += "• Ping the printer IP address to verify network connectivity"
        $suggestions += "• Check firewall settings on both client and printer"
        $suggestions += "• Verify printer network settings (IP, subnet, gateway)"
        $suggestions += "• Test with telnet to printer port 9100 for raw printing"
    }

    # Shared printer suggestions
    if ($Printer.PortName -and $Printer.PortName.StartsWith('\\')) {
        $suggestions += "For shared printer issues:"
        $suggestions += "• Verify the print server is online and accessible"
        $suggestions += "• Check user permissions for accessing the shared printer"
        $suggestions += "• Ensure print spooler service is running on the print server"
        $suggestions += "• Try reconnecting to the shared printer"
    }

    # USB printer suggestions
    if ($Printer.PortName -and $Printer.PortName.StartsWith('USB')) {
        $suggestions += "For USB printer issues:"
        $suggestions += "• Try a different USB port, preferably USB 2.0 or higher"
        $suggestions += "• Test with a different USB cable"
        $suggestions += "• Update or reinstall USB printer drivers"
        $suggestions += "• Check Windows Device Manager for USB device errors"
    }

    # Driver-related suggestions
    if ($Printer.DriverName) {
        $suggestions += "Driver troubleshooting:"
        $suggestions += "• Download latest drivers from manufacturer's website"
        $suggestions += "• Try removing and reinstalling the printer with updated drivers"
        $suggestions += "• For older printers, try compatibility mode drivers"
    }

    # General troubleshooting steps
    $suggestions += "General troubleshooting steps:"
    $suggestions += "• Restart the Print Spooler service (services.msc)"
    $suggestions += "• Clear the print queue of any stuck jobs"
    $suggestions += "• Check Windows Event Viewer for printing-related errors"
    $suggestions += "• Try printing a Windows test page"
    $suggestions += "• Verify printer is set as default if intended"

    return $suggestions
}

function Get-PrintingPortReference {
    <#
    .SYNOPSIS
        Provides comprehensive reference information about printing ports and protocols
    #>
    [CmdletBinding()]
    param()

    return @{
        NetworkPorts = @{
            '9100' = @{
                Protocol = 'RAW/Socket'
                Description = 'Standard TCP/IP printing port for raw data'
                CommonUse = 'Direct IP printing, HP JetDirect compatible printers'
                Security = 'No authentication, unencrypted'
                Troubleshooting = @(
                    'Test connectivity with: telnet <printer_ip> 9100',
                    'Check if printer supports raw printing',
                    'Verify firewall allows port 9100 traffic'
                )
            }
            '515' = @{
                Protocol = 'LPR/LPD'
                Description = 'Line Printer Daemon protocol'
                CommonUse = 'Unix/Linux printing, legacy network printing'
                Security = 'Basic authentication, unencrypted'
                Troubleshooting = @(
                    'Ensure LPD service is running on printer',
                    'Check queue name configuration',
                    'Verify proper LPR client setup'
                )
            }
            '631' = @{
                Protocol = 'IPP/IPPS'
                Description = 'Internet Printing Protocol over HTTP/HTTPS'
                CommonUse = 'Modern network printing, CUPS compatibility'
                Security = 'Supports authentication and encryption (IPPS)'
                Troubleshooting = @(
                    'Test with: http://<printer_ip>:631',
                    'Check CUPS compatibility',
                    'Verify SSL/TLS settings for IPPS'
                )
            }
            '80' = @{
                Protocol = 'HTTP'
                Description = 'Web-based printer management interface'
                CommonUse = 'Printer configuration, status monitoring'
                Security = 'Basic authentication, unencrypted'
                Troubleshooting = @(
                    'Access via web browser: http://<printer_ip>',
                    'Check web server status on printer',
                    'Verify network connectivity'
                )
            }
            '443' = @{
                Protocol = 'HTTPS'
                Description = 'Secure web-based printer management'
                CommonUse = 'Secure printer configuration and monitoring'
                Security = 'SSL/TLS encrypted with authentication'
                Troubleshooting = @(
                    'Access via: https://<printer_ip>',
                    'Check SSL certificate validity',
                    'Verify secure connection settings'
                )
            }
            '161' = @{
                Protocol = 'SNMP'
                Description = 'Simple Network Management Protocol'
                CommonUse = 'Printer status monitoring, management'
                Security = 'Community strings (v1/v2), authentication (v3)'
                Troubleshooting = @(
                    'Test SNMP connectivity with snmpwalk',
                    'Verify community string settings',
                    'Check SNMP version compatibility'
                )
            }
            '5985/5986' = @{
                Protocol = 'WinRM'
                Description = 'Windows Remote Management'
                CommonUse = 'Windows-based remote printer management'
                Security = 'Windows authentication, HTTPS encryption (5986)'
                Troubleshooting = @(
                    'Check WinRM service configuration',
                    'Verify authentication credentials',
                    'Test with: Test-NetConnection -Port 5985'
                )
            }
        }
        WindowsPorts = @{
            '135' = @{
                Protocol = 'RPC Endpoint Mapper'
                Description = 'Remote Procedure Call endpoint mapper'
                CommonUse = 'Windows RPC services coordination'
                Security = 'Windows authentication'
                Troubleshooting = @(
                    'Check RPC service status',
                    'Verify firewall RPC rules',
                    'Test with: rpcping'
                )
            }
            '445' = @{
                Protocol = 'SMB/CIFS'
                Description = 'Server Message Block file/printer sharing'
                CommonUse = 'Windows file and printer sharing'
                Security = 'Windows authentication, SMB encryption'
                Troubleshooting = @(
                    'Test with: net use \\<server>\<share>',
                    'Check SMB service status',
                    'Verify share permissions'
                )
            }
            '139' = @{
                Protocol = 'NetBIOS'
                Description = 'NetBIOS Session Service'
                CommonUse = 'Legacy Windows networking (older SMB)'
                Security = 'Windows authentication'
                Troubleshooting = @(
                    'Check NetBIOS service status',
                    'Verify NetBIOS name resolution',
                    'Consider upgrading to SMB direct (port 445)'
                )
            }
            '593' = @{
                Protocol = 'HTTP-RPC-EPMAP'
                Description = 'HTTP RPC endpoint mapper'
                CommonUse = 'RPC over HTTP for firewalled environments'
                Security = 'Windows authentication over HTTP'
                Troubleshooting = @(
                    'Check HTTP-RPC proxy settings',
                    'Verify RPC over HTTP configuration',
                    'Test HTTP connectivity'
                )
            }
        }
        PortTypes = @{
            'LPT' = @{
                Description = 'Parallel port (Legacy)'
                Protocol = 'IEEE 1284'
                MaxSpeed = '2 Mbps'
                ConnectionType = 'Physical parallel cable'
                CommonIssues = @('Cable problems', 'Port conflicts', 'Driver issues')
                ModernAlternative = 'USB or network printing'
            }
            'COM' = @{
                Description = 'Serial port'
                Protocol = 'RS-232'
                MaxSpeed = '115.2 Kbps'
                ConnectionType = 'Physical serial cable'
                CommonIssues = @('Baud rate mismatch', 'Flow control problems', 'Cable issues')
                ModernAlternative = 'USB or network printing'
            }
            'USB' = @{
                Description = 'Universal Serial Bus'
                Protocol = 'USB 1.1/2.0/3.0'
                MaxSpeed = '480 Mbps (USB 2.0), 5 Gbps (USB 3.0)'
                ConnectionType = 'Physical USB cable'
                CommonIssues = @('Driver problems', 'Power management', 'Hub limitations')
                ModernAlternative = 'Network printing for shared access'
            }
            'IP' = @{
                Description = 'Standard TCP/IP Port'
                Protocol = 'TCP/IP (Raw/LPR)'
                MaxSpeed = 'Network dependent (10 Mbps - 10+ Gbps)'
                ConnectionType = 'Network (Ethernet/WiFi)'
                CommonIssues = @('IP conflicts', 'Network connectivity', 'Firewall blocking')
                ModernAlternative = 'WSD or IPP for better features'
            }
            'WSD' = @{
                Description = 'Web Services on Devices'
                Protocol = 'WS-Discovery over TCP/IP'
                MaxSpeed = 'Network dependent'
                ConnectionType = 'Network (Ethernet/WiFi)'
                CommonIssues = @('Discovery problems', 'Firewall blocking', 'Service dependencies')
                ModernAlternative = 'IPP for cross-platform compatibility'
            }
        }
        TroubleshootingGuide = @{
            NetworkConnectivity = @(
                '1. Test basic connectivity: ping <printer_ip>',
                '2. Check specific port: Test-NetConnection -ComputerName <printer_ip> -Port <port>',
                '3. Verify firewall settings on both client and printer',
                '4. Check network infrastructure (switches, routers, DHCP)',
                '5. Validate printer network configuration'
            )
            DriverIssues = @(
                '1. Download latest drivers from manufacturer website',
                '2. Remove printer and drivers completely',
                '3. Restart print spooler service',
                '4. Install fresh drivers and recreate printer',
                '5. Try generic/universal drivers if specific ones fail'
            )
            ServiceProblems = @(
                '1. Check Print Spooler service status (services.msc)',
                '2. Restart Print Spooler: net stop spooler && net start spooler',
                '3. Clear spooler directory: C:\Windows\System32\spool\PRINTERS',
                '4. Check event logs for service errors',
                '5. Verify service account permissions'
            )
            ShareAccess = @(
                '1. Test share access: net use \\<server>\<share>',
                '2. Check user permissions on shared printer',
                '3. Verify print server is accessible and online',
                '4. Test with different user account if needed',
                '5. Check Group Policy printer deployment'
            )
        }
        BestPractices = @{
            NetworkPrinting = @(
                'Use static IP addresses for printers',
                'Document printer IP addresses and locations',
                'Implement proper VLAN segmentation',
                'Use DHCP reservations instead of static IPs when possible',
                'Monitor printer status with SNMP',
                'Keep firmware updated for security and features'
            )
            ClientConfiguration = @(
                'Install correct drivers before adding printer',
                'Use standard TCP/IP ports for better reliability',
                'Configure appropriate timeouts for network printers',
                'Test print functionality after installation',
                'Document printer settings for future reference'
            )
            Security = @(
                'Use HTTPS/IPPS for secure printing when available',
                'Implement access controls on shared printers',
                'Regularly update printer firmware',
                'Use SNMP v3 with authentication',
                'Monitor print logs for security events',
                'Consider print servers for centralized management'
            )
        }
    }
}

function Test-SpoolDirectoryHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [Parameter(Mandatory)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Analyzing spool directory health on $ComputerName", $null, 'SpoolDirectory')

        # Get spool directory path from registry
        $spoolDir = "C:\Windows\System32\spool\PRINTERS"  # Default
        try {
            $regValue = Invoke-CimMethod -ClassName StdRegProv -MethodName GetStringValue -Arguments @{
                hDefKey = [uint32]2147483650  # HKEY_LOCAL_MACHINE
                sSubKeyName = "SYSTEM\CurrentControlSet\Control\Print"
                sValueName = "DefaultSpoolDirectory"
            } -CimSession $CimSession

            if ($regValue.ReturnValue -eq 0 -and $regValue.sValue) {
                $spoolDir = $regValue.sValue
                $Logger.WriteDebug("Retrieved spool directory from registry: $spoolDir", $null, 'SpoolDirectory')
            }
        }
        catch {
            $Logger.WriteWarning("Could not read spool directory from registry, using default", @{
                Error = $_.Exception.Message
                DefaultPath = $spoolDir
            }, 'SpoolDirectory')
        }

        # Analyze disk space
        $driveLetter = ($spoolDir -replace "^([A-Za-z]):.*", '$1')
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($driveLetter):'" -CimSession $CimSession

        $diskAnalysis = @{
            Drive = "$driveLetter`:"
            TotalSizeGB = [math]::Round($disk.Size / 1GB, 2)
            FreeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            UsedSpaceGB = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
            FreeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
            FileSystem = $disk.FileSystem
        }

        # Analyze spool files
        $spoolFileAnalysis = @{
            SpoolDirectory = $spoolDir
            FileCount = 0
            TotalSizeMB = 0
            OldestFile = $null
            NewestFile = $null
            LargeFiles = @()
        }

        try {
            $spoolPath = $spoolDir.Replace('\', '\\')
            $spoolFiles = Get-CimInstance -ClassName CIM_DataFile -Filter "Path='$spoolPath\\'" -CimSession $CimSession

            if ($spoolFiles) {
                $spoolFileAnalysis.FileCount = $spoolFiles.Count
                $spoolFileAnalysis.TotalSizeMB = [math]::Round(($spoolFiles | Measure-Object FileSize -Sum).Sum / 1MB, 2)

                $sortedFiles = $spoolFiles | Sort-Object CreationDate
                $spoolFileAnalysis.OldestFile = $sortedFiles | Select-Object -First 1 | ForEach-Object {
                    @{
                        Name = $_.Name
                        SizeMB = [math]::Round($_.FileSize / 1MB, 2)
                        CreationDate = $_.CreationDate
                    }
                }
                $spoolFileAnalysis.NewestFile = $sortedFiles | Select-Object -Last 1 | ForEach-Object {
                    @{
                        Name = $_.Name
                        SizeMB = [math]::Round($_.FileSize / 1MB, 2)
                        CreationDate = $_.CreationDate
                    }
                }

                # Files larger than 10MB
                $spoolFileAnalysis.LargeFiles = $spoolFiles | Where-Object { $_.FileSize -gt 10MB } | ForEach-Object {
                    @{
                        Name = $_.Name
                        SizeMB = [math]::Round($_.FileSize / 1MB, 2)
                        CreationDate = $_.CreationDate
                    }
                }
            }
        }
        catch {
            $Logger.WriteWarning("Could not analyze spool files", @{
                Error = $_.Exception.Message
                SpoolDirectory = $spoolDir
            }, 'SpoolDirectory')
        }

        # Health assessment
        $healthMetrics = @{
            HasAdequateDiskSpace = $diskAnalysis.FreeSpaceGB -ge 2
            DiskSpaceHealthy = $diskAnalysis.FreeSpacePercent -ge 15
            SpoolFileCountHealthy = $spoolFileAnalysis.FileCount -le 100
            NoLargeStuckFiles = $spoolFileAnalysis.LargeFiles.Count -eq 0
        }

        $overallHealthy = $healthMetrics.HasAdequateDiskSpace -and
                         $healthMetrics.DiskSpaceHealthy -and
                         $spoolFileAnalysis.FileCount -lt 500

        $analysis = @{
            SpoolDirectory = $spoolFileAnalysis
            DiskSpace = $diskAnalysis
            HealthMetrics = $healthMetrics
            OverallHealthy = $overallHealthy
            Recommendations = @()
        }

        # Generate recommendations
        if (-not $healthMetrics.HasAdequateDiskSpace) {
            $analysis.Recommendations += "Critical: Less than 2GB free disk space remaining"
        }
        if (-not $healthMetrics.DiskSpaceHealthy) {
            $analysis.Recommendations += "Warning: Less than 15% free disk space remaining"
        }
        if (-not $healthMetrics.SpoolFileCountHealthy) {
            $analysis.Recommendations += "Warning: High number of spool files ($($spoolFileAnalysis.FileCount)) may indicate stuck jobs"
        }
        if ($spoolFileAnalysis.LargeFiles.Count -gt 0) {
            $analysis.Recommendations += "Warning: $($spoolFileAnalysis.LargeFiles.Count) large spool files detected"
        }

        $Logger.WriteInfo("Spool directory analysis completed", @{
            OverallHealthy = $overallHealthy
            FreeSpaceGB = $diskAnalysis.FreeSpaceGB
            SpoolFileCount = $spoolFileAnalysis.FileCount
        }, 'SpoolDirectory')

        return @{
            IsSuccessful = $overallHealthy
            Analysis = $analysis
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "SpoolDirectory-$ComputerName" -Logger $Logger
}

function Get-PrintServerEventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [int]$EventCount = 30,
        [int]$HoursBack = 24,
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Retrieving print service event logs from $ComputerName", @{
            EventCount = $EventCount
            HoursBack = $HoursBack
        }, 'EventLogs')

        $startTime = (Get-Date).AddHours(-$HoursBack)
        $eventLogs = @{
            PrintServiceAdmin = @()
            PrintServiceOperational = @()
            System = @()
            Application = @()
        }

        $eventAnalysis = @{
            TotalEvents = 0
            ErrorEvents = 0
            WarningEvents = 0
            InformationEvents = 0
            CriticalPatterns = @()
            RecentCritical = @()
        }

        # Print Service Admin Log
        try {
            $adminEvents = Get-WinEvent -ComputerName $ComputerName -LogName "Microsoft-Windows-PrintService/Admin" -MaxEvents $EventCount -ErrorAction Stop |
                          Where-Object { $_.TimeCreated -ge $startTime }

            $eventLogs.PrintServiceAdmin = $adminEvents | ForEach-Object {
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    Id = $_.Id
                    Level = $_.Level
                    LevelDisplayName = $_.LevelDisplayName
                    ProviderName = $_.ProviderName
                    Message = $_.Message
                    MachineName = $_.MachineName
                    UserId = $_.UserId
                }
            }

            $Logger.WriteInfo("Retrieved $($adminEvents.Count) Print Service Admin events", $null, 'EventLogs')
        }
        catch {
            $Logger.WriteWarning("Could not retrieve Print Service Admin events", @{
                Error = $_.Exception.Message
            }, 'EventLogs')
        }

        # Print Service Operational Log
        try {
            $operationalEvents = Get-WinEvent -ComputerName $ComputerName -LogName "Microsoft-Windows-PrintService/Operational" -MaxEvents ($EventCount * 2) -ErrorAction SilentlyContinue |
                                Where-Object { $_.TimeCreated -ge $startTime }

            if ($operationalEvents) {
                $eventLogs.PrintServiceOperational = $operationalEvents | ForEach-Object {
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        Id = $_.Id
                        Level = $_.Level
                        LevelDisplayName = $_.LevelDisplayName
                        ProviderName = $_.ProviderName
                        Message = $_.Message
                        MachineName = $_.MachineName
                    }
                }

                $Logger.WriteInfo("Retrieved $($operationalEvents.Count) Print Service Operational events", $null, 'EventLogs')
            }
        }
        catch {
            $Logger.WriteDebug("Could not retrieve Print Service Operational events (may not be enabled)", @{
                Error = $_.Exception.Message
            }, 'EventLogs')
        }

        # System Events (Print-related)
        try {
            $systemEvents = Get-WinEvent -ComputerName $ComputerName -LogName "System" -MaxEvents ($EventCount * 3) -ErrorAction SilentlyContinue |
                           Where-Object { $_.TimeCreated -ge $startTime -and ($_.ProviderName -like "*Print*" -or $_.ProviderName -like "*Spooler*") }

            if ($systemEvents) {
                $eventLogs.System = $systemEvents | ForEach-Object {
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        Id = $_.Id
                        Level = $_.Level
                        LevelDisplayName = $_.LevelDisplayName
                        ProviderName = $_.ProviderName
                        Message = $_.Message
                        MachineName = $_.MachineName
                    }
                }

                $Logger.WriteInfo("Retrieved $($systemEvents.Count) print-related System events", $null, 'EventLogs')
            }
        }
        catch {
            $Logger.WriteWarning("Could not retrieve System events", @{
                Error = $_.Exception.Message
            }, 'EventLogs')
        }

        # Analyze all events
        $allEvents = @()
        $allEvents += $eventLogs.PrintServiceAdmin
        $allEvents += $eventLogs.PrintServiceOperational
        $allEvents += $eventLogs.System

        $eventAnalysis.TotalEvents = $allEvents.Count
        $eventAnalysis.ErrorEvents = ($allEvents | Where-Object Level -eq 2).Count
        $eventAnalysis.WarningEvents = ($allEvents | Where-Object Level -eq 3).Count
        $eventAnalysis.InformationEvents = ($allEvents | Where-Object Level -eq 4).Count

        # Look for critical patterns
        $criticalKeywords = @('failed', 'error', 'timeout', 'denied', 'unavailable', 'corrupt')
        $eventAnalysis.CriticalPatterns = $allEvents | Where-Object {
            $message = $_.Message
            $criticalKeywords | Where-Object { $message -match $_ }
        }

        $eventAnalysis.RecentCritical = $allEvents | Where-Object { $_.Level -le 2 -and $_.TimeCreated -ge (Get-Date).AddHours(-4) }

        $Logger.WriteInfo("Event log analysis completed", $eventAnalysis, 'EventLogs')

        return @{
            IsSuccessful = $true
            Analysis = $eventAnalysis
            Events = $eventLogs
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "EventLogs-$ComputerName" -Logger $Logger -MaxRetries 1
}

# =============================================================================
# ADVANCED REPORT GENERATION WITH INTERACTIVE FEATURES
# =============================================================================

function Export-ComprehensiveHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$DiagnosticResult,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [object]$Logger,
        [switch]$AutoOpen
    )

    try {
        $Logger.WriteInfo("Generating comprehensive HTML report", @{
            OutputPath = $OutputPath
            ServerName = $DiagnosticResult.ServerName
        }, 'Reporting')

        $htmlContent = Generate-HtmlReportContent -DiagnosticResult $DiagnosticResult

        $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8

        if ($AutoOpen) {
            try {
                Start-Process $OutputPath
                $Logger.WriteInfo("HTML report opened automatically", @{ Path = $OutputPath }, 'Reporting')
            }
            catch {
                $Logger.WriteWarning("Could not auto-open HTML report", @{
                    Path = $OutputPath
                    Error = $_.Exception.Message
                }, 'Reporting')
            }
        }

        $Logger.WriteInfo("HTML report generated successfully", @{
            Path = $OutputPath
            FileSize = (Get-Item $OutputPath).Length
        }, 'Reporting')

        return @{
            Success = $true
            FilePath = $OutputPath
            FileSize = (Get-Item $OutputPath).Length
        }
    }
    catch {
        $Logger.WriteError("Failed to generate HTML report", @{
            Error = $_.Exception.Message
            OutputPath = $OutputPath
        }, 'Reporting')

        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Generate-HtmlReportContent {
    param([object]$DiagnosticResult)

    $healthScore = $DiagnosticResult.GetHealthScore()
    $overallStatus = if ($DiagnosticResult.OverallHealth) { "HEALTHY" } else { "ISSUES DETECTED" }
    $statusClass = if ($DiagnosticResult.OverallHealth) { "status-success" } else { "status-failure" }

    $testSummaryHtml = Generate-TestSummarySection -DiagnosticResult $DiagnosticResult
    $detailsHtml = Generate-TestDetailsSection -DiagnosticResult $DiagnosticResult
    $warningsErrorsHtml = Generate-WarningsErrorsSection -DiagnosticResult $DiagnosticResult
    $performanceHtml = Generate-PerformanceSection -DiagnosticResult $DiagnosticResult
    $chartsHtml = Generate-ChartsSection -DiagnosticResult $DiagnosticResult

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Print Server Diagnostic Report - $($DiagnosticResult.ServerName)</title>
    <style>
        :root {
            --primary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --info: #3498db;
            --light: #ecf0f1;
            --dark: #34495e;
        }

        * { box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }

        .header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--dark) 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5rem;
            font-weight: 300;
        }

        .header .subtitle {
            opacity: 0.9;
            font-size: 1.1rem;
        }

        .status-overview {
            display: flex;
            justify-content: center;
            padding: 30px;
            background: var(--light);
        }

        .status-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            min-width: 300px;
        }

        .status-success {
            border-left: 5px solid var(--success);
        }

        .status-failure {
            border-left: 5px solid var(--danger);
        }

        .status-title {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .health-score {
            font-size: 3rem;
            font-weight: bold;
            color: var(--success);
            margin: 20px 0;
        }

        .status-failure .health-score {
            color: var(--danger);
        }

        .content {
            padding: 30px;
        }

        .section {
            margin-bottom: 40px;
        }

        .section h2 {
            color: var(--primary);
            border-bottom: 2px solid var(--info);
            padding-bottom: 10px;
            margin-bottom: 25px;
        }

        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }

        .test-item {
            background: white;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }

        .test-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }

        .test-item.success {
            border-left: 4px solid var(--success);
        }

        .test-item.failure {
            border-left: 4px solid var(--danger);
        }

        .test-name {
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 10px;
            color: var(--primary);
        }

        .test-status {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9rem;
        }

        .status-pass {
            background: var(--success);
            color: white;
        }

        .status-fail {
            background: var(--danger);
            color: white;
        }

        .test-duration {
            color: #666;
            font-size: 0.9rem;
            margin-top: 10px;
        }

        .expandable {
            cursor: pointer;
            user-select: none;
        }

        .expandable:before {
            content: "▼ ";
            transition: transform 0.2s;
        }

        .expandable.collapsed:before {
            transform: rotate(-90deg);
            display: inline-block;
        }

        .expandable-content {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }

        .warning-item, .error-item {
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }

        .warning-item {
            background: #fff3cd;
            border-color: var(--warning);
            color: #856404;
        }

        .error-item {
            background: #f8d7da;
            border-color: var(--danger);
            color: #721c24;
        }

        .performance-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }

        .metric-card {
            background: linear-gradient(135deg, var(--info) 0%, #5dade2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }

        .metric-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .metric-label {
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .footer {
            background: var(--light);
            padding: 30px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }

        .chart-container {
            margin: 20px 0;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        @media (max-width: 768px) {
            .header h1 { font-size: 2rem; }
            .status-card { min-width: auto; margin: 10px; }
            .content { padding: 20px; }
            .test-grid { grid-template-columns: 1fr; }
        }
    </style>
    <script>
        function toggleExpandable(element) {
            const content = element.nextElementSibling;
            const isCollapsed = content.style.display === 'none';

            content.style.display = isCollapsed ? 'block' : 'none';
            element.classList.toggle('collapsed', !isCollapsed);
        }

        function exportData(format) {
            const data = {
                serverName: '$($DiagnosticResult.ServerName)',
                testDate: '$($DiagnosticResult.TestDate)',
                overallHealth: $($DiagnosticResult.OverallHealth.ToString().ToLower()),
                healthScore: $healthScore,
                summary: $(ConvertTo-Json $DiagnosticResult.Summary -Compress),
                details: $(ConvertTo-Json $DiagnosticResult.Details -Compress -Depth 3),
                warnings: $(ConvertTo-Json $DiagnosticResult.Warnings -Compress),
                errors: $(ConvertTo-Json $DiagnosticResult.Errors -Compress)
            };

            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'diagnostic-data.json';
            a.click();
            URL.revokeObjectURL(url);
        }

        document.addEventListener('DOMContentLoaded', function() {
            // Initialize expandable sections
            document.querySelectorAll('.expandable').forEach(element => {
                const content = element.nextElementSibling;
                if (content) {
                    content.style.display = 'none';
                    element.classList.add('collapsed');
                }
            });
        });
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Print Server Diagnostic Report</h1>
            <div class="subtitle">
                Server: $($DiagnosticResult.ServerName) |
                Generated: $($DiagnosticResult.TestDate.ToString('yyyy-MM-dd HH:mm:ss')) |
                Session: $($DiagnosticResult.SessionId)
            </div>
        </div>

        <div class="status-overview">
            <div class="status-card $statusClass">
                <div class="status-title">$overallStatus</div>
                <div class="health-score">$healthScore%</div>
                <div>Health Score</div>
                <div style="margin-top: 15px; font-size: 0.9rem;">
                    Version: $($DiagnosticResult.Version)
                </div>
            </div>
        </div>

        <div class="content">
            <div class="section">
                <h2>Test Results Overview</h2>
                $testSummaryHtml
            </div>

            <div class="section">
                <h2>Performance Metrics</h2>
                $performanceHtml
            </div>

            <div class="section">
                <h2>Visual Analytics</h2>
                $chartsHtml
            </div>

            <div class="section">
                <h2 class="expandable" onclick="toggleExpandable(this)">Detailed Test Results</h2>
                <div class="expandable-content">
                    $detailsHtml
                </div>
            </div>

            <div class="section">
                <h2>Issues and Recommendations</h2>
                $warningsErrorsHtml
            </div>

            <div class="section">
                <h2>Export Options</h2>
                <button onclick="exportData('json')" style="padding: 10px 20px; background: var(--info); color: white; border: none; border-radius: 5px; cursor: pointer; margin: 5px;">
                    Export Raw Data (JSON)
                </button>
                <button onclick="window.print()" style="padding: 10px 20px; background: var(--primary); color: white; border: none; border-radius: 5px; cursor: pointer; margin: 5px;">
                    Print Report
                </button>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Enhanced Print Server Diagnostic Tool v$($DiagnosticResult.Version)</p>
            <p>Report generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $env:USERNAME on $env:COMPUTERNAME</p>
        </div>
    </div>
</body>
</html>
"@
}

function Generate-TestSummarySection {
    param([object]$DiagnosticResult)

    $html = '<div class="test-grid">'

    foreach ($test in $DiagnosticResult.Summary.GetEnumerator()) {
        $status = if ($test.Value) { 'success' } else { 'failure' }
        $statusText = if ($test.Value) { 'PASS' } else { 'FAIL' }
        $statusClass = if ($test.Value) { 'status-pass' } else { 'status-fail' }

        $duration = if ($DiagnosticResult.PerformanceMetrics.ContainsKey($test.Key)) {
            "$([math]::Round($DiagnosticResult.PerformanceMetrics[$test.Key], 1))ms"
        } else { "N/A" }

        $html += @"
            <div class="test-item $status">
                <div class="test-name">$($test.Key)</div>
                <span class="test-status $statusClass">$statusText</span>
                <div class="test-duration">Duration: $duration</div>
            </div>
"@
    }

    $html += '</div>'
    return $html
}

function Generate-TestDetailsSection {
    param([object]$DiagnosticResult)

    $html = ''
    foreach ($test in $DiagnosticResult.Details.GetEnumerator()) {
        $detailsJson = $test.Value | ConvertTo-Json -Depth 3 -Compress | ConvertTo-Html -Fragment
        $html += @"
            <h4 class="expandable" onclick="toggleExpandable(this)">$($test.Key) Details</h4>
            <div class="expandable-content">
                <pre>$($test.Value | ConvertTo-Json -Depth 3)</pre>
            </div>
"@
    }
    return $html
}

function Generate-WarningsErrorsSection {
    param([object]$DiagnosticResult)

    $html = ''

    if ($DiagnosticResult.Warnings.Count -gt 0) {
        $html += '<h3>Warnings</h3>'
        foreach ($warning in $DiagnosticResult.Warnings) {
            $message = if ($warning -is [string]) { $warning } else { $warning.Message }
            $timestamp = if ($warning -is [string]) { '' } else { " ($($warning.Timestamp.ToString('HH:mm:ss')))" }
            $html += "<div class='warning-item'>$message$timestamp</div>"
        }
    }

    if ($DiagnosticResult.Errors.Count -gt 0) {
        $html += '<h3>Errors</h3>'
        foreach ($error in $DiagnosticResult.Errors) {
            $message = if ($error -is [string]) { $error } else { $error.Message }
            $timestamp = if ($error -is [string]) { '' } else { " ($($error.Timestamp.ToString('HH:mm:ss')))" }
            $html += "<div class='error-item'>$message$timestamp</div>"
        }
    }

    if ($DiagnosticResult.Warnings.Count -eq 0 -and $DiagnosticResult.Errors.Count -eq 0) {
        $html += '<p style="color: var(--success); font-weight: bold;">No issues detected! The print server appears to be functioning properly.</p>'
    }

    return $html
}

function Generate-PerformanceSection {
    param([object]$DiagnosticResult)

    if ($DiagnosticResult.PerformanceMetrics.Count -eq 0) {
        return '<p>No performance metrics available.</p>'
    }

    $totalDuration = ($DiagnosticResult.PerformanceMetrics.Values | Measure-Object -Sum).Sum
    $avgDuration = [math]::Round($totalDuration / $DiagnosticResult.PerformanceMetrics.Count, 1)
    $slowestTest = ($DiagnosticResult.PerformanceMetrics.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1)
    $fastestTest = ($DiagnosticResult.PerformanceMetrics.GetEnumerator() | Sort-Object Value | Select-Object -First 1)

    return @"
        <div class="performance-metrics">
            <div class="metric-card">
                <div class="metric-value">$([math]::Round($totalDuration, 0))ms</div>
                <div class="metric-label">Total Duration</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${avgDuration}ms</div>
                <div class="metric-label">Average Test Time</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($DiagnosticResult.PerformanceMetrics.Count)</div>
                <div class="metric-label">Tests Executed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($slowestTest.Key)</div>
                <div class="metric-label">Slowest Test ($([math]::Round($slowestTest.Value, 1))ms)</div>
            </div>
        </div>
"@
}

function Generate-ChartsSection {
    param([object]$DiagnosticResult)

    $successCount = ($DiagnosticResult.Summary.Values | Where-Object { $_ -eq $true }).Count
    $failCount = ($DiagnosticResult.Summary.Values | Where-Object { $_ -eq $false }).Count
    $successPercent = if ($DiagnosticResult.Summary.Count -gt 0) { [math]::Round(($successCount / $DiagnosticResult.Summary.Count) * 100, 1) } else { 0 }

    return @"
        <div class="chart-container">
            <h4>Test Results Distribution</h4>
            <div style="display: flex; align-items: center; justify-content: center; gap: 30px;">
                <div style="text-align: center;">
                    <div style="width: 100px; height: 100px; border-radius: 50%; background: conic-gradient(var(--success) 0deg ${successPercent * 3.6}deg, var(--danger) ${successPercent * 3.6}deg 360deg); display: flex; align-items: center; justify-content: center; font-weight: bold; color: white; font-size: 1.2rem;">
                        $successPercent%
                    </div>
                    <div style="margin-top: 10px; font-weight: bold;">Success Rate</div>
                </div>
                <div>
                    <div style="margin: 5px 0;"><span style="color: var(--success);">●</span> Passed: $successCount</div>
                    <div style="margin: 5px 0;"><span style="color: var(--danger);">●</span> Failed: $failCount</div>
                    <div style="margin: 5px 0;"><span style="color: var(--warning);">●</span> Warnings: $($DiagnosticResult.Warnings.Count)</div>
                    <div style="margin: 5px 0;"><span style="color: var(--danger);">●</span> Errors: $($DiagnosticResult.Errors.Count)</div>
                </div>
            </div>
        </div>
"@
}

# =============================================================================
# GUI INTERFACE WITH REAL-TIME UPDATES
# =============================================================================

function Show-DiagnosticResultsGui {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$DiagnosticResult,
        [object]$Logger
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        # Create main form
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Print Server Diagnostic Results - $($DiagnosticResult.ServerName)"
        $form.Size = New-Object System.Drawing.Size(1000, 700)
        $form.StartPosition = 'CenterScreen'
        $form.Icon = [System.Drawing.SystemIcons]::Computer

        # Create tab control
        $tabControl = New-Object System.Windows.Forms.TabControl
        $tabControl.Dock = 'Fill'
        $form.Controls.Add($tabControl)

        # Overview Tab
        $overviewTab = New-Object System.Windows.Forms.TabPage
        $overviewTab.Text = "Overview"
        $tabControl.TabPages.Add($overviewTab)

        # Create overview panel
        $overviewPanel = New-Object System.Windows.Forms.Panel
        $overviewPanel.Dock = 'Fill'
        $overviewPanel.AutoScroll = $true
        $overviewTab.Controls.Add($overviewPanel)

        # Header panel
        $headerPanel = New-Object System.Windows.Forms.Panel
        $headerPanel.Height = 100
        $headerPanel.Dock = 'Top'
        $headerPanel.BackColor = if ($DiagnosticResult.OverallHealth) { [System.Drawing.Color]::LightGreen } else { [System.Drawing.Color]::LightCoral }
        $overviewPanel.Controls.Add($headerPanel)

        # Header label
        $headerLabel = New-Object System.Windows.Forms.Label
        $headerLabel.Text = "Server: $($DiagnosticResult.ServerName)`nTest Date: $($DiagnosticResult.TestDate)`nOverall Health: $(if ($DiagnosticResult.OverallHealth) { 'HEALTHY' } else { 'ISSUES DETECTED' })`nHealth Score: $($DiagnosticResult.GetHealthScore())%"
        $headerLabel.Font = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Bold)
        $headerLabel.Dock = 'Fill'
        $headerLabel.TextAlign = 'MiddleCenter'
        $headerPanel.Controls.Add($headerLabel)

        # Results ListView
        $listView = New-Object System.Windows.Forms.ListView
        $listView.View = 'Details'
        $listView.FullRowSelect = $true
        $listView.GridLines = $true
        $listView.Location = New-Object System.Drawing.Point(10, 110)
        $listView.Size = New-Object System.Drawing.Size(960, 400)
        $listView.Columns.Add("Test", 150) | Out-Null
        $listView.Columns.Add("Result", 80) | Out-Null
        $listView.Columns.Add("Duration", 100) | Out-Null
        $listView.Columns.Add("Category", 120) | Out-Null
        $listView.Columns.Add("Details", 400) | Out-Null
        $overviewPanel.Controls.Add($listView)

        # Populate ListView
        foreach ($test in $DiagnosticResult.Summary.GetEnumerator()) {
            $item = $listView.Items.Add($test.Key)
            $item.SubItems.Add($(if ($test.Value) { "PASS" } else { "FAIL" })) | Out-Null

            $duration = if ($DiagnosticResult.PerformanceMetrics.ContainsKey($test.Key)) {
                "$([math]::Round($DiagnosticResult.PerformanceMetrics[$test.Key], 1))ms"
            } else { "N/A" }
            $item.SubItems.Add($duration) | Out-Null

            $category = if ($DiagnosticResult.Details.ContainsKey($test.Key) -and $DiagnosticResult.Details[$test.Key].Category) {
                $DiagnosticResult.Details[$test.Key].Category
            } else { "General" }
            $item.SubItems.Add($category) | Out-Null

            $details = if ($DiagnosticResult.Details.ContainsKey($test.Key)) {
                $detailsObj = $DiagnosticResult.Details[$test.Key]
                if ($detailsObj.Details) {
                    ($detailsObj.Details | ConvertTo-Json -Compress -Depth 2).Substring(0, [Math]::Min(100, ($detailsObj.Details | ConvertTo-Json -Compress -Depth 2).Length))
                } else { "No details available" }
            } else { "No details available" }
            $item.SubItems.Add($details) | Out-Null

            if ($test.Value) {
                $item.BackColor = [System.Drawing.Color]::LightGreen
            } else {
                $item.BackColor = [System.Drawing.Color]::LightCoral
            }
        }

        # Details Tab
        $detailsTab = New-Object System.Windows.Forms.TabPage
        $detailsTab.Text = "Details"
        $tabControl.TabPages.Add($detailsTab)

        # Details text box
        $detailsTextBox = New-Object System.Windows.Forms.TextBox
        $detailsTextBox.Multiline = $true
        $detailsTextBox.ScrollBars = 'Both'
        $detailsTextBox.Dock = 'Fill'
        $detailsTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
        $detailsTextBox.ReadOnly = $true
        $detailsTextBox.Text = $DiagnosticResult | ConvertTo-Json -Depth 4
        $detailsTab.Controls.Add($detailsTextBox)

        # Issues Tab (if any)
        if ($DiagnosticResult.Warnings.Count -gt 0 -or $DiagnosticResult.Errors.Count -gt 0) {
            $issuesTab = New-Object System.Windows.Forms.TabPage
            $issuesTab.Text = "Issues ($($DiagnosticResult.Warnings.Count + $DiagnosticResult.Errors.Count))"
            $tabControl.TabPages.Add($issuesTab)

            $issuesTextBox = New-Object System.Windows.Forms.TextBox
            $issuesTextBox.Multiline = $true
            $issuesTextBox.ScrollBars = 'Both'
            $issuesTextBox.Dock = 'Fill'
            $issuesTextBox.ReadOnly = $true

            $issuesText = ""
            if ($DiagnosticResult.Warnings.Count -gt 0) {
                $issuesText += "WARNINGS:`r`n"
                foreach ($warning in $DiagnosticResult.Warnings) {
                    $message = if ($warning -is [string]) { $warning } else { $warning.Message }
                    $issuesText += "- $message`r`n"
                }
                $issuesText += "`r`n"
            }

            if ($DiagnosticResult.Errors.Count -gt 0) {
                $issuesText += "ERRORS:`r`n"
                foreach ($error in $DiagnosticResult.Errors) {
                    $message = if ($error -is [string]) { $error } else { $error.Message }
                    $issuesText += "- $message`r`n"
                }
            }

            $issuesTextBox.Text = $issuesText
            $issuesTab.Controls.Add($issuesTextBox)
        }

        # Status bar
        $statusBar = New-Object System.Windows.Forms.StatusBar
        $statusBar.Text = "Diagnostic completed at $($DiagnosticResult.TestDate) | Session: $($DiagnosticResult.SessionId)"
        $form.Controls.Add($statusBar)

        # Show form
        $Logger.WriteInfo("Displaying GUI interface", @{
            WindowTitle = $form.Text
            TabCount = $tabControl.TabPages.Count
        }, 'GUI')

        $form.ShowDialog() | Out-Null
    }
    catch {
        $Logger.WriteError("Failed to display GUI interface", @{
            Error = $_.Exception.Message
        }, 'GUI')
        Write-Warning "Could not display GUI interface: $($_.Exception.Message)"
    }
}

# =============================================================================
# MAIN DIAGNOSTIC ORCHESTRATION ENGINE
# =============================================================================

function Start-ClientSidePrinterDiagnostic {
    <#
    .SYNOPSIS
        Performs comprehensive client-side printer diagnostics without requiring administrative privileges
    .DESCRIPTION
        This function provides a full diagnostic suite for client-side printer testing that works
        with standard user permissions. It enumerates accessible printers, tests connectivity,
        provides detailed printer information, port analysis, and actionable troubleshooting suggestions.
    #>
    [CmdletBinding()]
    param(
        [string]$LogPath,
        [bool]$ExportResults,
        [bool]$ShowGui,
        [string]$ConfigPath,
        [bool]$Detailed
    )

    # Initialize configuration manager
    $configManager = New-ConfigurationManager -ConfigPath $ConfigPath

    # Initialize logger
    $logger = New-DiagnosticLogger -LogDirectory $LogPath -WriteToConsole $true -WriteToFile $true -LogLevel $configManager.GetValue('logging.level', 'INFO')
    $logger.WriteInfo("Starting client-side printer diagnostic", @{
        Version = $script:DiagnosticVersion
        SessionId = $script:SessionId
        Detailed = $Detailed
        UserContext = $env:USERNAME
        ComputerName = $env:COMPUTERNAME
    }, 'ClientMode')

    # Initialize result object
    $result = New-DiagnosticResult -ServerName "Client: $env:COMPUTERNAME"
    $result.Configuration = $configManager.Configuration

    # Calculate total steps for progress tracking
    $totalSteps = 5  # Base client-side tests
    if ($Detailed) {
        $totalSteps += 2  # Additional detailed analysis
    }

    # Setup progress tracking
    $progress = New-ProgressTracker -TotalSteps $totalSteps -Activity "Client-Side Printer Diagnostic"

    try {
        # Step 1: Check local print spooler service
        $progress.UpdateProgress("Checking local Print Spooler service", "Verifying print service status")
        $spoolerResult = Test-LocalPrintSpooler -Logger $logger
        $result.AddTest('LocalSpooler', ($spoolerResult.Success -and $spoolerResult.Result.IsSuccessful), $spoolerResult, $spoolerResult.Duration, 'System')

        # Step 2: Enumerate accessible printers
        $progress.UpdateProgress("Enumerating accessible printers", "Discovering local and network printers")
        $printerResult = Get-ClientSidePrinters -Logger $logger -IncludeDetailedInfo:$Detailed
        $result.AddTest('ClientPrinters', ($printerResult.Success -and $printerResult.Result.IsSuccessful), $printerResult, $printerResult.Duration, 'Printers')

        # Step 3: Test default printer functionality
        $progress.UpdateProgress("Testing default printer", "Checking default printer configuration and connectivity")
        $defaultPrinterResult = Test-DefaultPrinter -Logger $logger
        $result.AddTest('DefaultPrinter', ($defaultPrinterResult.Success -and $defaultPrinterResult.Result.IsSuccessful), $defaultPrinterResult, $defaultPrinterResult.Duration, 'Printers')

        # Step 4: Analyze print queue and jobs
        $progress.UpdateProgress("Analyzing print queue", "Checking for stuck jobs and queue health")
        $queueResult = Test-ClientPrintQueue -Logger $logger
        $result.AddTest('PrintQueue', $queueResult.Success, $queueResult, $queueResult.Duration, 'Queues')

        # Step 5: Generate comprehensive troubleshooting report
        $progress.UpdateProgress("Generating troubleshooting suggestions", "Analyzing issues and creating actionable recommendations")
        $troubleshootingResult = Generate-ClientTroubleshootingReport -PrinterResult $printerResult -Logger $logger
        $result.AddTest('Troubleshooting', $true, $troubleshootingResult, 0)

        # Detailed analysis steps
        if ($Detailed) {
            # Step 6: Driver analysis
            $progress.UpdateProgress("Analyzing printer drivers", "Checking driver versions and compatibility")
            $driverResult = Test-ClientPrinterDrivers -PrinterResult $printerResult -Logger $logger
            $result.AddTest('DriverAnalysis', $driverResult.Success, $driverResult, $driverResult.Duration, 'System')

            # Step 7: Port reference and best practices
            $progress.UpdateProgress("Generating port reference", "Creating comprehensive port and protocol guide")
            $portReference = Get-PrintingPortReference
            $result.AddTest('PortReference', $true, $portReference, 0)
        }

        # Calculate overall health
        $result.CalculateOverallHealth()

        # Handle exports and GUI
        if ($ExportResults) {
            $progress.UpdateProgress("Exporting results", "Generating HTML, JSON, and CSV reports") # Don't increment
            Export-DiagnosticResults -DiagnosticResult $result -OutputPath $LogPath -Logger $logger -AutoOpen
        }

        if ($ShowGui) {
            $progress.UpdateProgress("Launching GUI", "Opening graphical interface") # Don't increment
            Show-DiagnosticGui -DiagnosticResult $result -Logger $logger
        }

        $progress.Complete()
        $logger.WriteInfo("Client-side printer diagnostic completed successfully", @{
            TotalTests = $result.Summary.Count
            SuccessfulTests = ($result.Summary.Values | Where-Object { $_ }).Count
            OverallHealth = $result.OverallHealth
        }, 'ClientMode')

        return $result

    }
    catch {
        $logger.WriteError("Fatal error during client-side diagnostic", @{
            Error = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
        }, 'ClientMode')

        $result.AddError("Fatal diagnostic error: $($_.Exception.Message)", 'System')
        $result.CalculateOverallHealth()
        return $result
    }
}

function Test-LocalPrintSpooler {
    <#
    .SYNOPSIS
        Tests the local Print Spooler service status and configuration
    #>
    [CmdletBinding()]
    param([object]$Logger)

    $operation = {
        $Logger.WriteInfo("Testing local Print Spooler service", $null, 'LocalService')

        $spoolerService = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue

        $result = @{
            ServiceExists = $null -ne $spoolerService
            ServiceStatus = if ($spoolerService) { $spoolerService.Status } else { 'NotFound' }
            ServiceStartType = if ($spoolerService) { $spoolerService.StartType } else { 'Unknown' }
            CanStart = $false
            CanStop = $false
            Issues = @()
            Suggestions = @()
        }

        if ($spoolerService) {
            $result.CanStart = $spoolerService.Status -eq 'Stopped'
            $result.CanStop = $spoolerService.Status -eq 'Running'

            # Check for common issues
            if ($spoolerService.Status -ne 'Running') {
                $result.Issues += "Print Spooler service is not running (Status: $($spoolerService.Status))"
                $result.Suggestions += "Start the Print Spooler service: net start spooler"
                $result.Suggestions += "Check Windows Event Viewer for service startup errors"
            }

            if ($spoolerService.StartType -eq 'Disabled') {
                $result.Issues += "Print Spooler service is disabled"
                $result.Suggestions += "Enable Print Spooler service: Set-Service -Name Spooler -StartupType Automatic"
            }

            # Check spooler directory
            $spoolDir = "$env:SystemRoot\System32\spool\PRINTERS"
            if (Test-Path $spoolDir) {
                $spoolFiles = Get-ChildItem -Path $spoolDir -ErrorAction SilentlyContinue
                $result.SpoolDirectory = @{
                    Path = $spoolDir
                    FileCount = $spoolFiles.Count
                    TotalSize = ($spoolFiles | Measure-Object Length -Sum).Sum
                }

                if ($spoolFiles.Count -gt 0) {
                    $result.Issues += "Print spooler directory contains $($spoolFiles.Count) files - may indicate stuck jobs"
                    $result.Suggestions += "Clear stuck print jobs by stopping spooler, deleting files, and restarting"
                }
            }
        } else {
            $result.Issues += "Print Spooler service not found on system"
            $result.Suggestions += "Reinstall Print Spooler service through Windows Features"
        }

        $Logger.WriteInfo("Local Print Spooler test completed", $result, 'LocalService')

        return @{
            IsSuccessful = $spoolerService -and $spoolerService.Status -eq 'Running'
            Issues = $result.Issues
            Suggestions = $result.Suggestions
            ServiceInfo = $result
            Duration = 0
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "LocalSpoolerTest" -Logger $Logger
}

function Test-DefaultPrinter {
    <#
    .SYNOPSIS
        Tests the default printer configuration and basic connectivity
    #>
    [CmdletBinding()]
    param([object]$Logger)

    $operation = {
        $Logger.WriteInfo("Testing default printer configuration", $null, 'DefaultPrinter')

        $result = @{
            HasDefaultPrinter = $false
            DefaultPrinterName = $null
            DefaultPrinterDetails = @{}
            ConnectivityTest = @{}
            Issues = @()
            Suggestions = @()
        }

        try {
            # Try multiple methods to get default printer
            $defaultPrinter = $null

            # Method 1: WMI
            try {
                $defaultPrinter = Get-CimInstance -ClassName Win32_Printer -Filter "Default=TRUE" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($defaultPrinter) {
                    $result.HasDefaultPrinter = $true
                    $result.DefaultPrinterName = $defaultPrinter.Name
                }
            } catch { }

            # Method 2: Registry fallback
            if (-not $defaultPrinter) {
                try {
                    $deviceReg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "Device" -ErrorAction SilentlyContinue
                    if ($deviceReg -and $deviceReg.Device) {
                        $deviceParts = $deviceReg.Device -split ','
                        if ($deviceParts.Count -gt 0) {
                            $result.HasDefaultPrinter = $true
                            $result.DefaultPrinterName = $deviceParts[0]
                        }
                    }
                } catch { }
            }

            # Method 3: Get-Printer cmdlet
            if (-not $result.HasDefaultPrinter -and (Get-Command Get-Printer -ErrorAction SilentlyContinue)) {
                try {
                    $allPrinters = Get-Printer -ErrorAction SilentlyContinue
                    $defaultPrinter = $allPrinters | Where-Object { $_.Name -eq $result.DefaultPrinterName } | Select-Object -First 1
                    if (-not $defaultPrinter) {
                        # Sometimes the default isn't properly marked, try first available
                        $defaultPrinter = $allPrinters | Select-Object -First 1
                        if ($defaultPrinter) {
                            $result.HasDefaultPrinter = $true
                            $result.DefaultPrinterName = $defaultPrinter.Name
                            $result.Issues += "No default printer set, using first available: $($defaultPrinter.Name)"
                        }
                    }
                } catch { }
            }

            if ($result.HasDefaultPrinter -and $result.DefaultPrinterName) {
                # Get detailed information about default printer
                if ($defaultPrinter) {
                    $result.DefaultPrinterDetails = @{
                        Name = $defaultPrinter.Name
                        PortName = if ($defaultPrinter.PortName) { $defaultPrinter.PortName } else { 'Unknown' }
                        DriverName = if ($defaultPrinter.DriverName) { $defaultPrinter.DriverName } else { 'Unknown' }
                        Status = if ($defaultPrinter.PrinterStatus) { $defaultPrinter.PrinterStatus } else { 'Unknown' }
                        Location = if ($defaultPrinter.Location) { $defaultPrinter.Location } else { 'Not specified' }
                        Shared = if ($defaultPrinter.PSObject.Properties.Name -contains 'Shared') { $defaultPrinter.Shared } else { $false }
                    }

                    # Test connectivity
                    $result.ConnectivityTest = Test-ClientPrinterConnectivity -PrinterName $result.DefaultPrinterName -Logger $Logger

                    # Analyze for issues
                    if ($defaultPrinter.PrinterStatus -eq 7) {
                        $result.Issues += "Default printer is offline"
                        $result.Suggestions += "Check printer power and connections"
                        $result.Suggestions += "For network printers, verify network connectivity"
                    }

                    if (-not $result.ConnectivityTest.CanPrint) {
                        $result.Issues += "Default printer connectivity test failed"
                        $result.Suggestions += "Check printer drivers and installation"
                        $result.Suggestions += "Try removing and re-adding the printer"
                    }
                }

                $result.Suggestions += "Test default printer with Windows test page"
                $result.Suggestions += "Check printer queue for stuck jobs"
            } else {
                $result.Issues += "No default printer is configured"
                $result.Suggestions += "Set a default printer through Settings > Printers & scanners"
                $result.Suggestions += "Install and configure at least one printer"
            }

        } catch {
            $result.Issues += "Error testing default printer: $($_.Exception.Message)"
            $result.Suggestions += "Check system printer configuration"
        }

        $Logger.WriteInfo("Default printer test completed", $result, 'DefaultPrinter')

        return @{
            IsSuccessful = $result.HasDefaultPrinter -and ($result.Issues.Count -eq 0)
            HasDefault = $result.HasDefaultPrinter
            PrinterName = $result.DefaultPrinterName
            Details = $result.DefaultPrinterDetails
            ConnectivityTest = $result.ConnectivityTest
            Issues = $result.Issues
            Suggestions = $result.Suggestions
            Duration = 0
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "DefaultPrinterTest" -Logger $Logger
}

function Test-ClientPrintQueue {
    <#
    .SYNOPSIS
        Analyzes the client-side print queue for issues and stuck jobs
    #>
    [CmdletBinding()]
    param([object]$Logger)

    $operation = {
        $Logger.WriteInfo("Analyzing client print queue", $null, 'PrintQueue')

        $result = @{
            QueueStatus = 'Unknown'
            JobCount = 0
            StuckJobs = @()
            OldJobs = @()
            LargeJobs = @()
            Issues = @()
            Suggestions = @()
            Statistics = @{}
        }

        try {
            # Get print jobs (requires appropriate permissions)
            $printJobs = @()

            if (Get-Command Get-PrintJob -ErrorAction SilentlyContinue) {
                try {
                    # Try to get all print jobs
                    $printJobs = Get-PrintJob -ErrorAction SilentlyContinue
                    $result.JobCount = $printJobs.Count
                    $result.QueueStatus = if ($printJobs.Count -eq 0) { 'Empty' } else { 'HasJobs' }
                } catch {
                    $Logger.WriteWarning("Cannot access print jobs: $($_.Exception.Message)", $null, 'PrintQueue')
                }
            }

            if ($result.JobCount -gt 0) {
                $currentTime = Get-Date

                foreach ($job in $printJobs) {
                    # Check for stuck jobs (jobs that have been in queue for too long)
                    if ($job.SubmittedTime -and ($currentTime - $job.SubmittedTime).TotalMinutes -gt 30) {
                        $result.StuckJobs += @{
                            JobId = $job.Id
                            PrinterName = $job.PrinterName
                            JobName = $job.JobName
                            Status = $job.JobStatus
                            SubmittedTime = $job.SubmittedTime
                            Size = $job.Size
                            User = $job.UserName
                        }
                    }

                    # Check for old jobs
                    if ($job.SubmittedTime -and ($currentTime - $job.SubmittedTime).TotalHours -gt 2) {
                        $result.OldJobs += $job
                    }

                    # Check for large jobs (>50MB)
                    if ($job.Size -gt 50MB) {
                        $result.LargeJobs += $job
                    }
                }

                # Generate statistics
                $result.Statistics = @{
                    TotalJobs = $result.JobCount
                    StuckJobsCount = $result.StuckJobs.Count
                    OldJobsCount = $result.OldJobs.Count
                    LargeJobsCount = $result.LargeJobs.Count
                    TotalQueueSize = ($printJobs | Measure-Object Size -Sum).Sum
                }

                # Identify issues and provide suggestions
                if ($result.StuckJobs.Count -gt 0) {
                    $result.Issues += "$($result.StuckJobs.Count) stuck print job(s) detected"
                    $result.Suggestions += "Clear stuck jobs: Get-PrintJob | Where-Object {`$_.JobStatus -eq 'Retained'} | Remove-PrintJob"
                    $result.Suggestions += "Restart Print Spooler if jobs persist: Restart-Service Spooler"
                }

                if ($result.LargeJobs.Count -gt 0) {
                    $result.Issues += "$($result.LargeJobs.Count) large print job(s) may cause performance issues"
                    $result.Suggestions += "Consider printing large documents in smaller sections"
                    $result.Suggestions += "Check printer memory capacity for large jobs"
                }

                if ($result.JobCount -gt 10) {
                    $result.Issues += "High number of print jobs in queue ($($result.JobCount))"
                    $result.Suggestions += "Review and clear unnecessary print jobs"
                    $result.Suggestions += "Check for recurring failed print attempts"
                }

            } else {
                $result.QueueStatus = 'Empty'
                $result.Statistics = @{
                    TotalJobs = 0
                    StuckJobsCount = 0
                    OldJobsCount = 0
                    LargeJobsCount = 0
                    TotalQueueSize = 0
                }
            }

            # Check print spooler directory as fallback
            $spoolDir = "$env:SystemRoot\System32\spool\PRINTERS"
            if (Test-Path $spoolDir) {
                $spoolFiles = Get-ChildItem -Path $spoolDir -File -ErrorAction SilentlyContinue
                if ($spoolFiles.Count -gt 0 -and $result.JobCount -eq 0) {
                    $result.Issues += "$($spoolFiles.Count) files found in spooler directory but no visible print jobs"
                    $result.Suggestions += "Files in spooler directory may indicate stuck jobs"
                    $result.Suggestions += "Stop spooler service, clear directory, and restart service"
                }
            }

        } catch {
            $result.Issues += "Error analyzing print queue: $($_.Exception.Message)"
            $result.Suggestions += "Run with elevated privileges for full queue access"
        }

        $Logger.WriteInfo("Print queue analysis completed", $result.Statistics, 'PrintQueue')

        return @{
            IsSuccessful = $result.Issues.Count -eq 0
            QueueStatus = $result.QueueStatus
            Statistics = $result.Statistics
            StuckJobs = $result.StuckJobs
            Issues = $result.Issues
            Suggestions = $result.Suggestions
            Duration = 0
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "PrintQueueTest" -Logger $Logger
}

function Generate-ClientTroubleshootingReport {
    <#
    .SYNOPSIS
        Generates comprehensive troubleshooting suggestions based on client-side printer analysis
    #>
    [CmdletBinding()]
    param(
        [object]$PrinterResult,
        [object]$Logger
    )

    $Logger.WriteInfo("Generating client troubleshooting report", $null, 'Troubleshooting')

    $report = @{
        CommonIssues = @{}
        PrinterSpecificSuggestions = @{}
        GeneralTroubleshootingSteps = @()
        PortReferences = @{}
        BestPractices = @{}
        QuickFixes = @()
    }

    # Get port reference information
    $portReference = Get-PrintingPortReference

    # Analyze printers for common issues
    if ($PrinterResult -and $PrinterResult.Printers) {
        foreach ($printer in $PrinterResult.Printers) {
            $printerIssues = @()
            $printerSuggestions = @()

            # Port-specific analysis
            if ($printer.PortName) {
                $portInfo = Get-PrinterPortInfo -PortName $printer.PortName -Logger $Logger
                $report.PortReferences[$printer.PortName] = $portInfo

                # Add port-specific suggestions
                $printerSuggestions += $portInfo.TroubleshootingTips
            }

            # Status-specific analysis
            if ($printer.ErrorSuggestions) {
                $printerSuggestions += $printer.ErrorSuggestions
            }

            # Connectivity analysis
            if ($printer.ConnectivityTest -and -not $printer.ConnectivityTest.CanPrint) {
                $printerIssues += "Connectivity test failed for $($printer.Name)"
                $printerSuggestions += "Check printer drivers and installation"
                $printerSuggestions += "Verify printer is powered on and accessible"
            }

            $report.PrinterSpecificSuggestions[$printer.Name] = @{
                Issues = $printerIssues
                Suggestions = $printerSuggestions
                PortInfo = if ($printer.PortInfo) { $printer.PortInfo } else { @{} }
            }
        }
    }

    # General troubleshooting steps
    $report.GeneralTroubleshootingSteps = @(
        "1. Verify Print Spooler service is running: Get-Service Spooler",
        "2. Clear print queue of stuck jobs: Get-PrintJob | Remove-PrintJob -Confirm:`$false",
        "3. Restart Print Spooler service: Restart-Service Spooler",
        "4. Update printer drivers from manufacturer website",
        "5. Check Windows Update for driver updates",
        "6. Run Windows built-in printer troubleshooter",
        "7. Verify printer connectivity (network/USB)",
        "8. Check printer status via manufacturer's software",
        "9. Print Windows test page to verify functionality",
        "10. Check Event Viewer for printing errors"
    )

    # Quick fixes
    $report.QuickFixes = @(
        @{
            Issue = "Print Spooler Not Running"
            Command = "Start-Service Spooler"
            Description = "Starts the Windows Print Spooler service"
        },
        @{
            Issue = "Clear All Print Jobs"
            Command = "Get-PrintJob | Remove-PrintJob -Confirm:`$false"
            Description = "Removes all pending print jobs"
        },
        @{
            Issue = "Restart Print Spooler"
            Command = "Restart-Service Spooler"
            Description = "Restarts the Print Spooler service to clear issues"
        },
        @{
            Issue = "Set Default Printer"
            Command = "(Get-Printer)[0] | Set-Printer -Default"
            Description = "Sets the first available printer as default"
        },
        @{
            Issue = "Test Network Connectivity"
            Command = "Test-NetConnection -ComputerName <PrinterIP> -Port 9100"
            Description = "Tests network connectivity to a network printer"
        }
    )

    # Best practices
    $report.BestPractices = $portReference.BestPractices

    # Common issues and solutions
    $report.CommonIssues = @{
        "Printer Offline" = @{
            Causes = @("Network connectivity", "Power issues", "Driver problems", "USB connection")
            Solutions = @("Check physical connections", "Restart printer", "Update drivers", "Check network settings")
        }
        "Jobs Stuck in Queue" = @{
            Causes = @("Corrupted print jobs", "Driver issues", "Spooler problems", "Printer errors")
            Solutions = @("Clear print queue", "Restart spooler service", "Update drivers", "Check printer status")
        }
        'No Default Printer' = @{
            Causes = @("No printers installed", "Default printer removed", "User profile issues")
            Solutions = @("Install printer", "Set default printer", "Check user permissions", "Recreate printer connection")
        }
        'Driver Issues' = @{
            Causes = @("Outdated drivers", "Incompatible drivers", "Corrupted installation", "Windows updates")
            Solutions = @("Download latest drivers", "Use Windows Update", "Remove and reinstall", "Try generic drivers")
        }
        'Network Printer Not Accessible' = @{
            Causes = @("Network connectivity", "Firewall blocking", "IP address changes", "Authentication issues")
            Solutions = @("Test network connectivity", "Check firewall rules", "Verify IP address", "Check credentials")
        }
    }

    $Logger.WriteInfo("Client troubleshooting report generated", @{
        PrinterCount = if ($PrinterResult.Printers) { $PrinterResult.Printers.Count } else { 0 }
        IssuesIdentified = $report.PrinterSpecificSuggestions.Count
        QuickFixes = $report.QuickFixes.Count
    }, 'Troubleshooting')

    return $report
}

function Test-ClientPrinterDrivers {
    <#
    .SYNOPSIS
        Analyzes printer drivers for compatibility and version issues
    #>
    [CmdletBinding()]
    param(
        [object]$PrinterResult,
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Analyzing client printer drivers", $null, 'DriverAnalysis')

        $result = @{
            DriversAnalyzed = 0
            UniqueDrivers = @{}
            Issues = @()
            Suggestions = @()
            DriverDetails = @()
            Statistics = @{}
        }

        try {
            if ($PrinterResult -and $PrinterResult.Printers) {
                $driverNames = $PrinterResult.Printers | Where-Object DriverName | Select-Object -ExpandProperty DriverName -Unique

                foreach ($driverName in $driverNames) {
                    $result.DriversAnalyzed++

                    $driverInfo = @{
                        Name = $driverName
                        PrintersUsing = ($PrinterResult.Printers | Where-Object { $_.DriverName -eq $driverName }).Count
                        Version = 'Unknown'
                        Provider = 'Unknown'
                        DriverDate = 'Unknown'
                        IsGeneric = $false
                        Issues = @()
                        Recommendations = @()
                    }

                    # Analyze driver characteristics
                    if ($driverName -match 'Generic|Microsoft|Universal|PCL|PostScript') {
                        $driverInfo.IsGeneric = $true
                        $driverInfo.Recommendations += "Consider using manufacturer-specific drivers for better features"
                    }

                    # Try to get detailed driver information using PrintUI or registry
                    try {
                        if (Get-Command Get-PrinterDriver -ErrorAction SilentlyContinue) {
                            $driverDetails = Get-PrinterDriver -Name $driverName -ErrorAction SilentlyContinue
                            if ($driverDetails) {
                                $driverInfo.Version = if ($driverDetails.MajorVersion) { "$($driverDetails.MajorVersion).$($driverDetails.MinorVersion)" } else { 'Unknown' }
                                $driverInfo.Provider = if ($driverDetails.Manufacturer) { $driverDetails.Manufacturer } else { 'Unknown' }
                            }
                        }
                    } catch {
                        $Logger.WriteWarning("Could not get detailed driver info for $driverName", $null, 'DriverAnalysis')
                    }

                    # Check for common driver issues
                    if ($driverName -match 'Unknown|Generic.*Text') {
                        $driverInfo.Issues += "Using generic or unknown driver"
                        $driverInfo.Recommendations += "Install proper manufacturer driver"
                    }

                    $result.UniqueDrivers[$driverName] = $driverInfo
                    $result.DriverDetails += $driverInfo
                }

                # Generate overall statistics
                $result.Statistics = @{
                    TotalPrinters = $PrinterResult.Printers.Count
                    UniqueDrivers = $result.DriversAnalyzed
                    GenericDrivers = ($result.DriverDetails | Where-Object IsGeneric).Count
                    ProblemsFound = ($result.DriverDetails | Where-Object { $_.Issues.Count -gt 0 }).Count
                }

                # Overall recommendations
                if ($result.Statistics.GenericDrivers -gt 0) {
                    $result.Issues += "$($result.Statistics.GenericDrivers) printer(s) using generic drivers"
                    $result.Suggestions += "Download manufacturer-specific drivers for better performance and features"
                }

                if ($result.Statistics.ProblemsFound -gt 0) {
                    $result.Issues += "$($result.Statistics.ProblemsFound) driver(s) have potential issues"
                    $result.Suggestions += "Review individual driver recommendations"
                    $result.Suggestions += "Consider updating all drivers through Windows Update"
                }

                $result.Suggestions += "Regularly check manufacturer websites for driver updates"
                $result.Suggestions += "Keep Windows Update enabled for automatic driver updates"

            } else {
                $result.Issues += "No printer information available for driver analysis"
            }

        } catch {
            $result.Issues += "Error analyzing drivers: $($_.Exception.Message)"
            $result.Suggestions += "Run analysis with elevated privileges for complete driver information"
        }

        $Logger.WriteInfo("Driver analysis completed", $result.Statistics, 'DriverAnalysis')

        return @{
            IsSuccessful = $result.Issues.Count -eq 0
            Statistics = $result.Statistics
            DriverDetails = $result.DriverDetails
            Issues = $result.Issues
            Suggestions = $result.Suggestions
            Duration = 0
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "DriverAnalysis" -Logger $Logger
}

function Start-ComprehensivePrintServerDiagnostic {
    [CmdletBinding()]
    param(
        [string]$ServerFqdn,
        [int[]]$Ports,
        [int[]]$ExtraPorts,
        [int]$EventCount,
        [string]$LogPath,
        [bool]$ExportResults,
        [bool]$ShowGui,
        [string]$ConfigPath,
        [bool]$Detailed,
        [bool]$Parallel,
        [int]$MaxThreads
    )

    # Initialize configuration manager
    $configManager = New-ConfigurationManager -ConfigPath $ConfigPath

    # Initialize logger
    $logger = New-DiagnosticLogger -LogDirectory $LogPath -WriteToConsole $true -WriteToFile $true -LogLevel $configManager.GetValue('logging.level', 'INFO')
    $logger.WriteInfo("Starting comprehensive print server diagnostic", @{
        Version = $script:DiagnosticVersion
        SessionId = $script:SessionId
        ServerFqdn = $ServerFqdn
        Detailed = $Detailed
        Parallel = $Parallel
    }, 'Main')

    # Initialize result object
    $result = New-DiagnosticResult -ServerName $ServerFqdn
    $result.Configuration = $configManager.Configuration

    # Combine all ports to test
    $allPorts = ($Ports + $ExtraPorts) | Sort-Object -Unique
    $logger.WriteInfo("Port testing configuration", @{
        StandardPorts = $Ports -join ','
        ExtraPorts = $ExtraPorts -join ','
        TotalPorts = $allPorts.Count
    }, 'Configuration')

    # Calculate total steps for progress tracking
    $totalSteps = 7  # Base tests
    if ($Detailed) {
        $totalSteps += 3  # Additional detailed tests
    }

    # Setup progress tracking
    $progress = New-ProgressTracker -TotalSteps $totalSteps -Activity "Print Server Diagnostic: $ServerFqdn"

    # Store system information
    $result.SystemInfo = @{
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        OperatingSystem = [System.Environment]::OSVersion.ToString()
        UserName = $env:USERNAME
        ComputerName = $env:COMPUTERNAME
        ExecutionTime = Get-Date
        ExecutionPolicy = (Get-ExecutionPolicy).ToString()
    }

    try {
        # Test 1: DNS Resolution with comprehensive analysis
        $progress.UpdateProgress("DNS Resolution", "Resolving $ServerFqdn and performing reverse lookup")
        $dnsOperation = {
            $logger.WriteInfo("Starting DNS resolution for $ServerFqdn", $null, 'DNS')

            $dnsResults = @{
                ForwardLookup = $null
                ReverseLookup = $null
                IPv4Addresses = @()
                IPv6Addresses = @()
                CanonicalName = $null
                TTL = $null
            }

            try {
                # Forward DNS lookup
                $dnsQuery = Resolve-DnsName -Name $ServerFqdn -ErrorAction Stop
                $dnsResults.ForwardLookup = $dnsQuery

                # Separate IPv4 and IPv6 addresses
                $dnsResults.IPv4Addresses = $dnsQuery | Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress
                $dnsResults.IPv6Addresses = $dnsQuery | Where-Object Type -eq 'AAAA' | Select-Object -ExpandProperty IPAddress

                # Get CNAME if available
                $cnameRecord = $dnsQuery | Where-Object Type -eq 'CNAME' | Select-Object -First 1
                if ($cnameRecord) {
                    $dnsResults.CanonicalName = $cnameRecord.NameHost
                }

                # Reverse DNS lookup for first IPv4 address
                if ($dnsResults.IPv4Addresses.Count -gt 0) {
                    try {
                        $reverseLookup = Resolve-DnsName -Name $dnsResults.IPv4Addresses[0] -ErrorAction Stop
                        $dnsResults.ReverseLookup = $reverseLookup
                        $logger.WriteInfo("Reverse DNS lookup successful", @{
                            IP = $dnsResults.IPv4Addresses[0]
                            PTR = $reverseLookup.NameHost
                        }, 'DNS')
                    }
                    catch {
                        $logger.WriteWarning("Reverse DNS lookup failed", @{
                            IP = $dnsResults.IPv4Addresses[0]
                            Error = $_.Exception.Message
                        }, 'DNS')
                    }
                }

                $success = ($dnsResults.IPv4Addresses.Count -gt 0) -or ($dnsResults.IPv6Addresses.Count -gt 0)
                $logger.WriteInfo("DNS resolution completed", @{
                    Success = $success
                    IPv4Count = $dnsResults.IPv4Addresses.Count
                    IPv6Count = $dnsResults.IPv6Addresses.Count
                }, 'DNS')

                return @{
                    IsSuccessful = $success
                    Results = $dnsResults
                }
            }
            catch {
                $logger.WriteError("DNS resolution failed", @{
                    ServerFqdn = $ServerFqdn
                    Error = $_.Exception.Message
                }, 'DNS')
                throw
            }
        }

        $dnsResult = Invoke-SafeOperation -Operation $dnsOperation -OperationName "DNS-$ServerFqdn" -Logger $logger
        $result.AddTest('DNS', $dnsResult.Success, $dnsResult.Result, $dnsResult.Duration, 'Network')

        if (-not $dnsResult.Success) {
            $result.AddError("DNS resolution failed: $($dnsResult.Error)", 'Network')
        }

        # Test 2: Network Connectivity with detailed analysis
        $progress.UpdateProgress("Network Connectivity", "Testing ICMP ping with statistics")
        $pingResult = Test-NetworkConnectivity -ComputerName $ServerFqdn -Count 4 -TimeoutSeconds 5 -Logger $logger -Config $configManager.Configuration
        $result.AddTest('Ping', $pingResult.Success, $pingResult.Result, $pingResult.Duration, 'Network')

        if (-not $pingResult.Success) {
            $result.AddWarning("ICMP ping failed - server may have ICMP disabled or firewall blocking", 'Network')
        } elseif ($pingResult.Result.Analysis.SuccessRate -lt 100) {
            $result.AddWarning("Intermittent ping failures detected ($($pingResult.Result.Analysis.SuccessRate)% success rate)", 'Network')
        }

        # Test 3: TCP Port Connectivity with parallel scanning
        $progress.UpdateProgress("Port Connectivity", "Scanning $($allPorts.Count) TCP ports")
        $portResult = Test-TcpPortsParallel -ComputerName $ServerFqdn -Ports $allPorts -TimeoutMs 5000 -ThrottleLimit $MaxThreads -Logger $logger -UseRunspacePool:$Parallel
        $result.AddTest('PortScan', $portResult.Success, $portResult.Result, $portResult.Duration, 'Network')

        if ($portResult.Success) {
            $openPortsCount = $portResult.Result.Analysis.OpenPorts
            if ($openPortsCount -lt ($allPorts.Count * 0.5)) {
                $result.AddWarning("Less than 50% of tested ports are open ($openPortsCount/$($allPorts.Count))", 'Network')
            }
            # Check for specific critical ports
            $criticalPorts = @(135, 445, 5985)  # RPC, SMB, WinRM
            $criticalPortResults = $portResult.Result.Results | Where-Object { $_.Port -in $criticalPorts }
            $closedCriticalPorts = $criticalPortResults | Where-Object { -not $_.IsOpen }
            if ($closedCriticalPorts.Count -gt 0) {
                $result.AddWarning("Critical management ports are closed: $($closedCriticalPorts.Port -join ', ')", 'Network')
            }
        } else {
            $result.AddError("Port connectivity test failed: $($portResult.Error)", 'Network')
        }

        # Test 4: CIM/WMI Session with protocol preference
        $progress.UpdateProgress("Management Connection", "Establishing CIM/WMI session with protocol fallback")
        $cimResult = New-SecureCimSession -ComputerName $ServerFqdn -TimeoutSeconds 30 -Logger $logger -ProtocolPreference @('Dcom', 'WSMan')
        $result.AddTest('CIM', $cimResult.Success, $cimResult.Result, $cimResult.Duration, 'Management')

        if ($cimResult.Success) {
            $cimSession = $cimResult.Result.Session
            $logger.WriteInfo("CIM session established successfully", @{
                Protocol = $cimResult.Result.Protocol
                ComputerName = $ServerFqdn
            }, 'Management')

            # Test 5: Print Services Analysis
            $progress.UpdateProgress("Print Services", "Analyzing print spooler and related services")
            $servicesResult = Test-PrintServerServices -ComputerName $ServerFqdn -CimSession $cimSession -Logger $logger
            $result.AddTest('PrintServices', $servicesResult.Success, $servicesResult.Result, $servicesResult.Duration, 'PrintServices')

            if (-not $servicesResult.Success) {
                $result.AddError("Critical print services are not running properly", 'PrintServices')
            }

            # Test 6: Print Shares Analysis
            $progress.UpdateProgress("Print Shares", "Testing print share accessibility and configuration")
            $sharesResult = Test-PrintServerShares -ComputerName $ServerFqdn -CimSession $cimSession -Logger $logger
            $result.AddTest('PrintShares', $sharesResult.Success, $sharesResult.Result, $sharesResult.Duration, 'PrintServices')

            if (-not $sharesResult.Success) {
                $result.AddWarning("Print share accessibility issues detected", 'PrintServices')
            }

            # Test 7: Printer Enumeration
            $progress.UpdateProgress("Printer Enumeration", "Discovering and analyzing installed printers")
            $printersResult = Get-PrintServerPrinters -ComputerName $ServerFqdn -CimSession $cimSession -Logger $logger
            $result.AddTest('Printers', $printersResult.Success, $printersResult.Result, $printersResult.Duration, 'PrintServices')

            if ($printersResult.Success) {
                $offlinePrinters = $printersResult.Result.Analysis.OfflinePrinters
                if ($offlinePrinters -gt 0) {
                    $result.AddWarning("$offlinePrinters printer(s) are currently offline", 'PrintServices')
                }

                $totalPrinters = $printersResult.Result.Analysis.TotalPrinters
                if ($totalPrinters -eq 0) {
                    $result.AddWarning("No printers found on the print server", 'PrintServices')
                }
            }

            # Detailed tests if requested
            if ($Detailed) {
                # Test 8: Spool Directory Health Analysis
                $progress.UpdateProgress("Spool Directory", "Analyzing spool directory health and disk space")
                $spoolResult = Test-SpoolDirectoryHealth -ComputerName $ServerFqdn -CimSession $cimSession -Logger $logger
                $result.AddTest('SpoolDirectory', $spoolResult.Success, $spoolResult.Result, $spoolResult.Duration, 'PrintServices')

                if ($spoolResult.Success -and $spoolResult.Result.Analysis.Recommendations.Count -gt 0) {
                    foreach ($recommendation in $spoolResult.Result.Analysis.Recommendations) {
                        $result.AddWarning($recommendation, 'SpoolDirectory')
                    }
                }

                # Test 9: Event Log Analysis
                $progress.UpdateProgress("Event Log Analysis", "Retrieving and analyzing print service events")
                $eventsResult = Get-PrintServerEventLogs -ComputerName $ServerFqdn -EventCount $EventCount -HoursBack 24 -Logger $logger
                $result.AddTest('EventLogs', $eventsResult.Success, $eventsResult.Result, $eventsResult.Duration, 'Monitoring')

                if ($eventsResult.Success) {
                    $errorEvents = $eventsResult.Result.Analysis.ErrorEvents
                    $warningEvents = $eventsResult.Result.Analysis.WarningEvents

                    if ($errorEvents -gt 0) {
                        $result.AddWarning("$errorEvents error events found in print service logs", 'Monitoring')
                    }

                    if ($eventsResult.Result.Analysis.RecentCritical.Count -gt 0) {
                        $result.AddWarning("$($eventsResult.Result.Analysis.RecentCritical.Count) critical events in the last 4 hours", 'Monitoring')
                    }
                }

                # Test 10: System Health Overview
                $progress.UpdateProgress("System Health", "Collecting system performance and health metrics")
                $systemHealthOperation = {
                    $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $cimSession
                    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession
                    $cpuInfo = Get-CimInstance -ClassName Win32_Processor -CimSession $cimSession | Select-Object -First 1

                    $healthMetrics = @{
                        ComputerInfo = @{
                            Name = $systemInfo.Name
                            Domain = $systemInfo.Domain
                            Manufacturer = $systemInfo.Manufacturer
                            Model = $systemInfo.Model
                            TotalPhysicalMemoryGB = [math]::Round($systemInfo.TotalPhysicalMemory / 1GB, 2)
                        }
                        OperatingSystem = @{
                            Caption = $osInfo.Caption
                            Version = $osInfo.Version
                            BuildNumber = $osInfo.BuildNumber
                            ServicePackMajorVersion = $osInfo.ServicePackMajorVersion
                            LastBootUpTime = $osInfo.LastBootUpTime
                            FreePhysicalMemoryMB = [math]::Round($osInfo.FreePhysicalMemory / 1024, 2)
                            FreeVirtualMemoryMB = [math]::Round($osInfo.FreeVirtualMemory / 1024, 2)
                        }
                        Processor = @{
                            Name = $cpuInfo.Name
                            NumberOfCores = $cpuInfo.NumberOfCores
                            NumberOfLogicalProcessors = $cpuInfo.NumberOfLogicalProcessors
                            MaxClockSpeed = $cpuInfo.MaxClockSpeed
                            LoadPercentage = $cpuInfo.LoadPercentage
                        }
                    }

                    return $healthMetrics
                }

                $systemHealthResult = Invoke-SafeOperation -Operation $systemHealthOperation -OperationName "SystemHealth-$ServerFqdn" -Logger $logger
                $result.AddTest('SystemHealth', $systemHealthResult.Success, $systemHealthResult.Result, $systemHealthResult.Duration, 'System')
            }

            # Cleanup CIM session
            try {
                Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
                $logger.WriteInfo("CIM session cleaned up successfully", $null, 'Management')
            }
            catch {
                $logger.WriteWarning("Failed to cleanup CIM session", @{ Error = $_.Exception.Message }, 'Management')
            }
        }
        else {
            # If CIM session failed, try basic tests without CIM when possible
            $logger.WriteWarning("CIM session failed, attempting basic diagnostic tests without CIM", @{
                CimError = $cimResult.Error
            }, 'Management')

            # Test 1: Basic Print Services (without CIM)
            $progress.UpdateProgress("Print Services (Basic)", "Testing print services without CIM")
            $servicesResult = Test-PrintServerServices -ComputerName $ServerFqdn -Logger $logger
            $result.AddTest('PrintServices', $servicesResult.Success, $servicesResult.Result, $servicesResult.Duration, 'PrintServices')

            if (-not $servicesResult.Success) {
                $result.AddWarning("Print services check completed with limited information due to CIM failure", 'PrintServices')
            }

            # Test 2: Basic Print Shares (try SMB connection)
            $progress.UpdateProgress("Print Shares (Basic)", "Testing basic print share access")
            try {
                $shareTestResult = @{
                    Success = $false
                    Duration = 0
                    Result = @{ Error = "Cannot test print shares without CIM access or elevated permissions"; Method = 'Limited' }
                }

                # Try to connect to default print share if server is accessible
                $testStart = Get-Date
                $printSharePath = "\\$ServerFqdn\print$"
                if (Test-Path $printSharePath -ErrorAction SilentlyContinue) {
                    $shareTestResult = @{
                        Success = $true
                        Duration = ((Get-Date) - $testStart).TotalMilliseconds
                        Result = @{
                            SharePath = $printSharePath
                            Accessible = $true
                            Method = 'SMB'
                            Message = "Basic print share access confirmed"
                        }
                    }
                } else {
                    $shareTestResult.Duration = ((Get-Date) - $testStart).TotalMilliseconds
                    $shareTestResult.Result.Message = "Print share not accessible or does not exist"
                }
            }
            catch {
                $shareTestResult = @{
                    Success = $false
                    Duration = 0
                    Result = @{ Error = $_.Exception.Message; Method = 'SMB' }
                }
            }
            $result.AddTest('PrintShares', $shareTestResult.Success, $shareTestResult.Result, $shareTestResult.Duration, 'PrintServices')

            # Test 3: Printers (limited without CIM)
            $result.AddTest('Printers', $false, @{
                Error = "Printer enumeration requires CIM/WMI access"
                Suggestion = "Run as administrator or use credentials with remote access permissions"
                Method = 'Limited'
            }, 0, 'PrintServices')

            if ($Detailed) {
                $result.AddTest('SpoolDirectory', $false, @{ Error = "Spool directory analysis requires CIM/WMI access" }, 0, 'PrintServices')
                $result.AddTest('SystemHealth', $false, @{ Error = "System health analysis requires CIM/WMI access" }, 0, 'System')
            }

            $result.AddWarning("Limited diagnostic mode: Some advanced tests require CIM/WMI access. To enable full diagnostics, run as administrator or provide credentials with remote management permissions. Error: $($cimResult.Error)", 'Management')
        }

        # Final progress update
        $progress.UpdateProgress("Finalizing", "Completing diagnostic analysis and generating reports")

        $progress.CompleteProgress()

        # Calculate final health score and add summary
        $result.CalculateOverallHealth()
        $healthScore = $result.GetHealthScore()

        $logger.WriteInfo("Diagnostic completed successfully", @{
            ServerName = $ServerFqdn
            OverallHealth = $result.OverallHealth
            HealthScore = $healthScore
            TotalTests = $result.Summary.Count
            PassedTests = ($result.Summary.Values | Where-Object { $_ }).Count
            WarningCount = $result.Warnings.Count
            ErrorCount = $result.Errors.Count
            TotalDuration = ($result.PerformanceMetrics.Values | Measure-Object -Sum).Sum
        }, 'Main')

        # Generate reports if requested
        if ($ExportResults) {
            $logger.WriteInfo("Generating diagnostic reports", @{ ExportResults = $true }, 'Reporting')

            # HTML Report
            $htmlPath = Join-Path $LogPath "PrintServerDiagnostic_$($ServerFqdn)_$script:SessionId.html"
            $htmlResult = Export-ComprehensiveHtmlReport -DiagnosticResult $result -OutputPath $htmlPath -Logger $logger -AutoOpen:$configManager.GetValue('reporting.autoOpen', $true)

            if ($htmlResult.Success) {
                $logger.WriteInfo("HTML report generated successfully", @{
                    Path = $htmlResult.FilePath
                    Size = $htmlResult.FileSize
                }, 'Reporting')
            }

            # JSON Report
            $jsonPath = Join-Path $LogPath "PrintServerDiagnostic_$($ServerFqdn)_$script:SessionId.json"
            try {
                $jsonData = @{
                    Metadata = @{
                        ExportTime = Get-Date
                        Version = $result.Version
                        SessionId = $result.SessionId
                        Generator = "Enhanced Print Server Diagnostic Tool"
                    }
                    DiagnosticResult = $result
                }
                $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                $logger.WriteInfo("JSON report generated successfully", @{
                    Path = $jsonPath
                    Size = (Get-Item $jsonPath).Length
                }, 'Reporting')
            }
            catch {
                $logger.WriteError("Failed to generate JSON report", @{
                    Path = $jsonPath
                    Error = $_.Exception.Message
                }, 'Reporting')
            }
        }

        # Show GUI if requested
        if ($ShowGui) {
            $logger.WriteInfo("Launching GUI interface", @{ ShowGui = $true }, 'GUI')
            Show-DiagnosticResultsGui -DiagnosticResult $result -Logger $logger
        }

        return $result

    }
    catch {
        $progress.CompleteProgress()
        $logger.WriteError("Diagnostic process failed", @{
            Error = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            ServerFqdn = $ServerFqdn
        }, 'Main')

        $result.AddError("Diagnostic process failed: $($_.Exception.Message)", 'Main')
        return $result
    }
    finally {
        # Ensure progress is always completed
        $progress.CompleteProgress()
    }
}

# =============================================================================
# CONSOLE OUTPUT AND SUMMARY FUNCTIONS
# =============================================================================

function Write-DiagnosticStatus {
    param(
        [string]$TestName,
        [bool]$IsSuccessful,
        [string]$AdditionalInfo = "",
        [double]$DurationMs = 0
    )

    $symbol = if ($IsSuccessful) { "[PASS]" } else { "[FAIL]" }
    $color = if ($IsSuccessful) { "Green" } else { "Red" }
    $duration = if ($DurationMs -gt 0) { " ($([math]::Round($DurationMs, 0))ms)" } else { "" }

    Write-Host ("{0,-35} {1} {2}{3}" -f $TestName, $symbol, $AdditionalInfo, $duration) -ForegroundColor $color
}

function Show-DiagnosticSummary {
    param([object]$DiagnosticResult)

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "COMPREHENSIVE PRINT SERVER DIAGNOSTIC SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "Server: $($DiagnosticResult.ServerName)" -ForegroundColor Cyan
    Write-Host "Session: $($DiagnosticResult.SessionId)" -ForegroundColor Gray
    Write-Host "Health Score: $($DiagnosticResult.GetHealthScore())%" -ForegroundColor $(if ($DiagnosticResult.OverallHealth) { 'Green' } else { 'Red' })
    Write-Host "Overall Status: $(if ($DiagnosticResult.OverallHealth) { 'HEALTHY [PASS]' } else { 'ISSUES DETECTED [FAIL]' })" -ForegroundColor $(if ($DiagnosticResult.OverallHealth) { 'Green' } else { 'Red' })
    Write-Host ""

    # Group tests by category
    $testsByCategory = @{}
    foreach ($test in $DiagnosticResult.Details.GetEnumerator()) {
        $category = if ($test.Value.Category) { $test.Value.Category } else { 'General' }
        if (-not $testsByCategory.ContainsKey($category)) {
            $testsByCategory[$category] = @()
        }
        $testsByCategory[$category] += @{
            Name = $test.Key
            Success = $DiagnosticResult.Summary[$test.Key]
            Duration = if ($DiagnosticResult.PerformanceMetrics.ContainsKey($test.Key)) { $DiagnosticResult.PerformanceMetrics[$test.Key] } else { 0 }
        }
    }

    # Display tests by category
    foreach ($category in $testsByCategory.Keys | Sort-Object) {
        Write-Host "$category Tests:" -ForegroundColor Yellow
        Write-Host ("-" * 40) -ForegroundColor Yellow

        foreach ($test in $testsByCategory[$category] | Sort-Object Name) {
            Write-DiagnosticStatus -TestName "  $($test.Name)" -IsSuccessful $test.Success -DurationMs $test.Duration
        }
        Write-Host ""
    }

    # Performance summary
    if ($DiagnosticResult.PerformanceMetrics.Count -gt 0) {
        $totalDuration = ($DiagnosticResult.PerformanceMetrics.Values | Measure-Object -Sum).Sum
        $avgDuration = [math]::Round($totalDuration / $DiagnosticResult.PerformanceMetrics.Count, 1)
        $slowestTest = $DiagnosticResult.PerformanceMetrics.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1

        Write-Host "Performance Metrics:" -ForegroundColor Yellow
        Write-Host ("-" * 40) -ForegroundColor Yellow
        Write-Host "  Total execution time: $([math]::Round($totalDuration, 0))ms" -ForegroundColor Gray
        Write-Host "  Average test time: ${avgDuration}ms" -ForegroundColor Gray
        Write-Host "  Slowest test: $($slowestTest.Key) ($([math]::Round($slowestTest.Value, 1))ms)" -ForegroundColor Gray
        Write-Host ""
    }

    # Issues summary
    if ($DiagnosticResult.Warnings.Count -gt 0) {
        Write-Host "WARNINGS ($($DiagnosticResult.Warnings.Count)):" -ForegroundColor Yellow
        Write-Host ("-" * 40) -ForegroundColor Yellow
        foreach ($warning in $DiagnosticResult.Warnings) {
            $message = if ($warning -is [string]) { $warning } else { $warning.Message }
            Write-Host "  • $message" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    if ($DiagnosticResult.Errors.Count -gt 0) {
        Write-Host "ERRORS ($($DiagnosticResult.Errors.Count)):" -ForegroundColor Red
        Write-Host ("-" * 40) -ForegroundColor Red
        foreach ($error in $DiagnosticResult.Errors) {
            $message = if ($error -is [string]) { $error } else { $error.Message }
            Write-Host "  • $message" -ForegroundColor Red
        }
        Write-Host ""
    }

    if ($DiagnosticResult.Warnings.Count -eq 0 -and $DiagnosticResult.Errors.Count -eq 0) {
        Write-Host "No issues detected! The print server appears to be functioning optimally." -ForegroundColor Green
        Write-Host ""
    }

    Write-Host "=" * 80 -ForegroundColor Cyan
}

# =============================================================================
# CLIENT-SIDE DIAGNOSTIC FUNCTIONS (NO ADMIN RIGHTS REQUIRED)
# =============================================================================

function Get-ClientSidePrinters {
    <#
    .SYNOPSIS
        Enumerates printers accessible to the current user without requiring admin rights.
    #>
    [CmdletBinding()]
    param(
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Enumerating client-accessible printers", $null, 'ClientPrinters')

        $printers = @()
        $detailedPrinters = @()

        try {
            # Method 1: Use Get-Printer (PowerShell 4.0+)
            if (Get-Command -Name Get-Printer -ErrorAction SilentlyContinue) {
                $Logger.WriteDebug("Using Get-Printer cmdlet for enumeration", $null, 'ClientPrinters')
                $printers += Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_ }
            }
        }
        catch {
            $Logger.WriteDebug("Get-Printer failed: $($_.Exception.Message)", $null, 'ClientPrinters')
        }

        try {
            # Method 2: WMI Win32_Printer (fallback)
            if ($printers.Count -eq 0) {
                $Logger.WriteDebug("Falling back to WMI Win32_Printer", $null, 'ClientPrinters')
                $wmiPrinters = Get-WmiObject -Class Win32_Printer -ErrorAction SilentlyContinue
                foreach ($wmiPrinter in $wmiPrinters) {
                    $printers += [PSCustomObject]@{
                        Name = $wmiPrinter.Name
                        PrinterStatus = $wmiPrinter.PrinterStatus
                        ShareName = $wmiPrinter.ShareName
                        PortName = $wmiPrinter.PortName
                        DriverName = $wmiPrinter.DriverName
                        Location = $wmiPrinter.Location
                        Comment = $wmiPrinter.Comment
                        Default = $wmiPrinter.Default
                        Shared = $wmiPrinter.Shared
                        Network = $wmiPrinter.Network
                        WorkOffline = $wmiPrinter.WorkOffline
                        Type = 'WMI'
                    }
                }
            }
        }
        catch {
            $Logger.WriteDebug("WMI enumeration failed: $($_.Exception.Message)", $null, 'ClientPrinters')
        }

        # Method 3: .NET PrinterSettings (additional validation)
        try {
            $Logger.WriteDebug("Validating printers using .NET PrinterSettings", $null, 'ClientPrinters')
            Add-Type -AssemblyName System.Drawing
            $installedPrinters = [System.Drawing.Printing.PrinterSettings]::InstalledPrinters

            foreach ($printerName in $installedPrinters) {
                if (-not ($printers | Where-Object { $_.Name -eq $printerName })) {
                    $printers += [PSCustomObject]@{
                        Name = $printerName
                        PrinterStatus = 'Unknown'
                        ShareName = $null
                        PortName = 'Unknown'
                        DriverName = 'Unknown'
                        Location = $null
                        Comment = $null
                        Default = $false
                        Shared = $false
                        Network = $false
                        WorkOffline = $false
                        Type = 'NET'
                    }
                }
            }
        }
        catch {
            $Logger.WriteDebug(".NET validation failed: $($_.Exception.Message)", $null, 'ClientPrinters')
        }

        # Enhance each printer with detailed information
        foreach ($printer in $printers) {
            $detailInfo = Get-DetailedPrinterInfo -PrinterName $printer.Name -Logger $Logger
            $portInfo = Get-PrinterPortInfo -PortName $printer.PortName -Logger $Logger

            $detailedPrinter = [PSCustomObject]@{
                Name = $printer.Name
                Status = Get-PrinterStatusDescription -PrinterStatus $printer.PrinterStatus
                ShareName = $printer.ShareName
                PortName = $printer.PortName
                PortType = $portInfo.Type
                PortDescription = $portInfo.Description
                DriverName = $printer.DriverName
                Location = $printer.Location
                Comment = $printer.Comment
                Default = $printer.Default
                Shared = $printer.Shared
                Network = $printer.Network
                WorkOffline = $printer.WorkOffline
                IsHealthy = (-not $printer.WorkOffline -and $printer.PrinterStatus -ne 7)
                Firmware = $detailInfo.Firmware
                Capabilities = $detailInfo.Capabilities
                ErrorSuggestions = Get-PrinterErrorSuggestions -Printer $printer -Logger $Logger
                LastTestTime = Get-Date
                Type = $printer.Type
            }

            $detailedPrinters += $detailedPrinter
        }

        $statistics = @{
            TotalPrinters = $printers.Count
            OnlinePrinters = ($detailedPrinters | Where-Object { $_.IsHealthy }).Count
            OfflinePrinters = ($detailedPrinters | Where-Object { $_.WorkOffline }).Count
            NetworkPrinters = ($detailedPrinters | Where-Object { $_.Network }).Count
            SharedPrinters = ($detailedPrinters | Where-Object { $_.Shared }).Count
            DefaultPrinter = ($detailedPrinters | Where-Object { $_.Default } | Select-Object -First 1 -ExpandProperty Name -ErrorAction SilentlyContinue)
        }

        $Logger.WriteInfo("Client printer enumeration completed", $statistics, 'ClientPrinters')

        return @{
            IsSuccessful = $printers.Count -gt 0
            Printers = $detailedPrinters
            Statistics = $statistics
            Method = 'Client'
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "ClientPrinters" -Logger $Logger
}

function Get-DetailedPrinterInfo {
    <#
    .SYNOPSIS
        Gets detailed printer information including firmware and capabilities.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PrinterName,
        [object]$Logger
    )

    $details = @{
        Firmware = 'Unknown'
        Capabilities = @{
            Color = $false
            Duplex = $false
            Stapling = $false
            MaxResolution = 'Unknown'
            SupportedMediaSizes = @()
        }
        PageCounts = @{
            TotalPages = 0
            ColorPages = 0
            BlackPages = 0
        }
        SupplyLevels = @()
    }

    try {
        # Try to get printer properties using Get-PrinterProperty (Windows 8+)
        if (Get-Command -Name Get-PrinterProperty -ErrorAction SilentlyContinue) {
            $Logger.WriteDebug("Attempting to get printer properties for $PrinterName", $null, 'PrinterDetails')

            try {
                $properties = Get-PrinterProperty -PrinterName $PrinterName -ErrorAction SilentlyContinue

                foreach ($prop in $properties) {
                    switch ($prop.PropertyName) {
                        'Firmware Version' { $details.Firmware = $prop.Value }
                        'Device Type' { $details.DeviceType = $prop.Value }
                        'Page Count' { $details.PageCounts.TotalPages = [int]$prop.Value }
                        'Color Print Count' { $details.PageCounts.ColorPages = [int]$prop.Value }
                        'Mono Print Count' { $details.PageCounts.BlackPages = [int]$prop.Value }
                    }
                }
            }
            catch {
                $Logger.WriteDebug("Get-PrinterProperty failed for $PrinterName`: $($_.Exception.Message)", $null, 'PrinterDetails')
            }
        }

        # Try WMI for additional details
        try {
            $wmiPrinter = Get-WmiObject -Class Win32_Printer -Filter "Name='$($PrinterName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
            if ($wmiPrinter) {
                if ($wmiPrinter.Capabilities) {
                    $details.Capabilities.Color = ($wmiPrinter.Capabilities -contains 4)
                    $details.Capabilities.Duplex = ($wmiPrinter.Capabilities -contains 7)
                }

                if ($wmiPrinter.MaxResolutionSupported) {
                    $details.Capabilities.MaxResolution = "$($wmiPrinter.MaxResolutionSupported) dpi"
                }

                if ($wmiPrinter.PaperSizesSupported) {
                    $details.Capabilities.SupportedMediaSizes = $wmiPrinter.PaperSizesSupported
                }
            }
        }
        catch {
            $Logger.WriteDebug("WMI printer details failed for $PrinterName`: $($_.Exception.Message)", $null, 'PrinterDetails')
        }

        # Try SNMP for network printers (if port indicates network printer)
        if ($PrinterName -match "IP_" -or $PrinterName -match "\\\\") {
            $Logger.WriteDebug("Attempting SNMP query for network printer $PrinterName", $null, 'PrinterDetails')
            $snmpDetails = Get-SNMPPrinterInfo -PrinterName $PrinterName -Logger $Logger
            if ($snmpDetails) {
                $details.Firmware = if ($snmpDetails.Firmware) { $snmpDetails.Firmware } else { $details.Firmware }
                $details.SupplyLevels = if ($snmpDetails.SupplyLevels) { $snmpDetails.SupplyLevels } else { @() }
            }
        }

    }
    catch {
        $Logger.WriteWarning("Failed to get detailed info for printer $PrinterName`: $($_.Exception.Message)", $null, 'PrinterDetails')
    }

    return $details
}

function Get-SNMPPrinterInfo {
    <#
    .SYNOPSIS
        Attempts to get printer information via SNMP (for network printers).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PrinterName,
        [object]$Logger
    )

    # This is a framework for SNMP queries - would require additional SNMP libraries
    # For now, return basic structure
    $Logger.WriteDebug("SNMP framework available for future enhancement", $null, 'SNMP')

    return @{
        Firmware = $null
        SupplyLevels = @()
        Model = $null
        SerialNumber = $null
    }
}

function Get-PrinterPortInfo {
    <#
    .SYNOPSIS
        Gets detailed information about printer ports and their usage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PortName,
        [object]$Logger
    )

    $portInfo = @{
        Name = $PortName
        Type = 'Unknown'
        Description = 'Unknown port type'
        Protocol = 'Unknown'
        Troubleshooting = @()
    }

    # Analyze port name to determine type
    switch -Regex ($PortName) {
        '^LPT\d+:?' {
            $portInfo.Type = 'Parallel'
            $portInfo.Description = 'Legacy parallel port (IEEE 1284)'
            $portInfo.Protocol = 'Centronics/IEEE 1284'
            $portInfo.Troubleshooting = @(
                'Check physical cable connection',
                'Verify parallel port is enabled in BIOS',
                'Ensure printer is powered on and ready',
                'Try different parallel cable'
            )
        }
        '^COM\d+:?' {
            $portInfo.Type = 'Serial'
            $portInfo.Description = 'Serial communication port (RS-232)'
            $portInfo.Protocol = 'RS-232 Serial'
            $portInfo.Troubleshooting = @(
                'Verify baud rate settings (usually 9600)',
                'Check flow control settings (XON/XOFF or RTS/CTS)',
                'Ensure correct serial cable (null-modem if required)',
                'Verify COM port settings in Device Manager'
            )
        }
        '^USB\d+' {
            $portInfo.Type = 'USB'
            $portInfo.Description = 'Universal Serial Bus connection'
            $portInfo.Protocol = 'USB 1.1/2.0/3.0'
            $portInfo.Troubleshooting = @(
                'Try different USB port (preferably USB 2.0)',
                'Use direct connection (avoid USB hubs if possible)',
                'Update or reinstall printer drivers',
                'Check Windows power management settings',
                'Verify USB cable is not damaged'
            )
        }
        '^IP_' {
            $portInfo.Type = 'TCP/IP'
            $portInfo.Description = 'Standard TCP/IP network port'
            $portInfo.Protocol = 'RAW (Port 9100) or LPR'
            $portInfo.Troubleshooting = @(
                'Ping printer IP address to verify connectivity',
                'Check firewall settings (allow ports 9100, 515)',
                'Verify printer IP configuration',
                'Test network cable and switch connectivity',
                'Try telnet to port 9100 for RAW or 515 for LPR'
            )
        }
        '^WSD-' {
            $portInfo.Type = 'WSD'
            $portInfo.Description = 'Web Services for Devices (WS-Discovery)'
            $portInfo.Protocol = 'WSD over HTTP/HTTPS'
            $portInfo.Troubleshooting = @(
                'Enable Network Discovery in Windows',
                'Check Windows Firewall (allow Network Discovery)',
                'Verify printer supports WS-Discovery',
                'Restart Print Spooler service',
                'Use printer IP address instead of WSD'
            )
        }
        '^\\\\.*\\.*' {
            $portInfo.Type = 'Network Share'
            $portInfo.Description = 'Shared network printer via SMB/CIFS'
            $portInfo.Protocol = 'SMB/CIFS (Port 445)'
            $portInfo.Troubleshooting = @(
                'Verify network connectivity to print server',
                'Check user permissions for printer access',
                'Ensure SMB/CIFS is enabled',
                'Try connecting with full UNC path',
                'Verify print server service is running'
            )
        }
        '^FILE:' {
            $portInfo.Type = 'File'
            $portInfo.Description = 'Print to file output'
            $portInfo.Protocol = 'File System'
            $portInfo.Troubleshooting = @(
                'Verify write permissions to target directory',
                'Check available disk space',
                'Ensure path is accessible'
            )
        }
        'PORTPROMPT' {
            $portInfo.Type = 'Prompt'
            $portInfo.Description = 'Prompt for port on each print job'
            $portInfo.Protocol = 'Dynamic'
            $portInfo.Troubleshooting = @(
                'This is normal behavior for this port type',
                'Select appropriate port when prompted',
                'Consider setting a specific port for consistency'
            )
        }
    }

    return $portInfo
}

function Get-PrintingPortReference {
    <#
    .SYNOPSIS
        Returns comprehensive reference of printing-related network ports.
    #>
    [CmdletBinding()]
    param()

    return @{
        # Standard Printing Ports
        9100 = @{
            Protocol = 'RAW/Socket Printing'
            Description = 'HP JetDirect compatible raw printing'
            Usage = 'Direct socket connection for fast printing'
            Troubleshooting = 'Most common for network printers'
        }
        515 = @{
            Protocol = 'LPR/LPD'
            Description = 'Line Printer Remote/Line Printer Daemon'
            Usage = 'Unix/Linux style printing protocol'
            Troubleshooting = 'Legacy protocol, slower than RAW'
        }
        631 = @{
            Protocol = 'IPP/IPPS'
            Description = 'Internet Printing Protocol (HTTP-based)'
            Usage = 'Modern web-based printing standard'
            Troubleshooting = 'Supports encryption and advanced features'
        }

        # Web Management Ports
        80 = @{
            Protocol = 'HTTP'
            Description = 'Web-based printer management'
            Usage = 'Access printer web interface'
            Troubleshooting = 'Open http://printer-ip in browser'
        }
        443 = @{
            Protocol = 'HTTPS'
            Description = 'Secure web-based printer management'
            Usage = 'Encrypted access to printer web interface'
            Troubleshooting = 'Open https://printer-ip in browser'
        }

        # SNMP Monitoring
        161 = @{
            Protocol = 'SNMP'
            Description = 'Simple Network Management Protocol'
            Usage = 'Monitor printer status, supply levels'
            Troubleshooting = 'Used by monitoring software'
        }

        # Windows-Specific Ports
        135 = @{
            Protocol = 'RPC Endpoint Mapper'
            Description = 'Windows RPC service location'
            Usage = 'Required for WMI/CIM printer management'
            Troubleshooting = 'Critical for Windows print management'
        }
        445 = @{
            Protocol = 'SMB/CIFS'
            Description = 'Server Message Block file and printer sharing'
            Usage = 'Windows network printer sharing'
            Troubleshooting = 'Required for \\server\printer connections'
        }
        139 = @{
            Protocol = 'NetBIOS Session Service'
            Description = 'Legacy Windows networking'
            Usage = 'NetBIOS name resolution for older systems'
            Troubleshooting = 'Fallback for SMB connections'
        }
        593 = @{
            Protocol = 'HTTP-RPC-EPMAP'
            Description = 'HTTP over RPC endpoint mapper'
            Usage = 'Alternative RPC communication method'
            Troubleshooting = 'Used when direct RPC is blocked'
        }

        # Windows Remote Management
        5985 = @{
            Protocol = 'WinRM HTTP'
            Description = 'Windows Remote Management over HTTP'
            Usage = 'PowerShell remoting and WMI over HTTP'
            Troubleshooting = 'Enable-PSRemoting to configure'
        }
        5986 = @{
            Protocol = 'WinRM HTTPS'
            Description = 'Windows Remote Management over HTTPS'
            Usage = 'Secure PowerShell remoting and WMI'
            Troubleshooting = 'Requires SSL certificate configuration'
        }
    }
}

function Get-PrinterStatusDescription {
    <#
    .SYNOPSIS
        Converts numeric printer status to human-readable description.
    #>
    [CmdletBinding()]
    param(
        [object]$PrinterStatus
    )

    switch ($PrinterStatus) {
        1 { return 'Other' }
        2 { return 'Unknown' }
        3 { return 'Idle (Ready)' }
        4 { return 'Printing' }
        5 { return 'Warmup' }
        6 { return 'Stopped Printing' }
        7 { return 'Offline' }
        8 { return 'Paused' }
        9 { return 'Error' }
        10 { return 'Busy' }
        11 { return 'Not Available' }
        12 { return 'Waiting' }
        13 { return 'Processing' }
        14 { return 'Initialization' }
        15 { return 'Power Save' }
        16 { return 'Pending Deletion' }
        17 { return 'I/O Active' }
        18 { return 'Manual Feed' }
        default { return "Status Code: $PrinterStatus" }
    }
}

function Get-PrinterErrorSuggestions {
    <#
    .SYNOPSIS
        Provides context-aware troubleshooting suggestions for printer issues.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Printer,
        [object]$Logger
    )

    $suggestions = @()

    # Status-based suggestions
    if ($Printer.WorkOffline) {
        $suggestions += @{
            Type = 'Offline'
            Severity = 'High'
            Issue = 'Printer is set to Work Offline'
            Solutions = @(
                'Right-click printer in Control Panel -> Uncheck "Use Printer Offline"',
                'Check network connectivity if network printer',
                'Verify printer is powered on and connected',
                'Restart Print Spooler service: net stop spooler && net start spooler'
            )
        }
    }

    if ($Printer.PrinterStatus -eq 7) {
        $suggestions += @{
            Type = 'Offline'
            Severity = 'High'
            Issue = 'Printer status indicates offline'
            Solutions = @(
                'Check physical printer power and connections',
                'Verify network connectivity for network printers',
                'Update or reinstall printer drivers',
                'Run Windows printer troubleshooter'
            )
        }
    }

    # Port-specific suggestions
    $portInfo = Get-PrinterPortInfo -PortName $Printer.PortName -Logger $Logger
    if ($portInfo.Troubleshooting.Count -gt 0) {
        $suggestions += @{
            Type = 'Port'
            Severity = 'Medium'
            Issue = "Port-specific guidance for $($portInfo.Type) connection"
            Solutions = $portInfo.Troubleshooting
        }
    }

    # Network printer specific
    if ($Printer.Network) {
        $suggestions += @{
            Type = 'Network'
            Severity = 'Medium'
            Issue = 'Network printer connectivity'
            Solutions = @(
                'Test network connectivity: ping printer-ip-address',
                'Verify firewall allows printing ports (9100, 515, 631)',
                'Check if printer DHCP reservation is configured',
                'Try connecting by IP address instead of hostname',
                'Verify DNS resolution if using hostname'
            )
        }
    }

    # Driver-related suggestions
    if ([string]::IsNullOrEmpty($Printer.DriverName) -or $Printer.DriverName -eq 'Unknown') {
        $suggestions += @{
            Type = 'Driver'
            Severity = 'High'
            Issue = 'Printer driver missing or unknown'
            Solutions = @(
                'Download latest driver from manufacturer website',
                'Run Windows Update to get generic drivers',
                'Try "Generic / Text Only" driver for basic printing',
                'Use "Add Printer" wizard to detect and install drivers'
            )
        }
    }

    return $suggestions
}

function Test-ClientPrintSpooler {
    <#
    .SYNOPSIS
        Tests the local print spooler service from client perspective.
    #>
    [CmdletBinding()]
    param(
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Testing local print spooler service", $null, 'ClientSpooler')

        $spoolerService = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        $spoolerResult = @{
            ServiceFound = $false
            ServiceRunning = $false
            ServiceStartType = 'Unknown'
            SpoolDirectory = $null
            SpoolSize = 0
            QueuedJobs = 0
            ErrorCount = 0
        }

        if ($spoolerService) {
            $spoolerResult.ServiceFound = $true
            $spoolerResult.ServiceRunning = ($spoolerService.Status -eq 'Running')
            $spoolerResult.ServiceStartType = $spoolerService.StartType

            # Get spool directory info
            try {
                $spoolPath = "${env:SystemRoot}\System32\spool\PRINTERS"
                if (Test-Path $spoolPath) {
                    $spoolerResult.SpoolDirectory = $spoolPath
                    $spoolFiles = Get-ChildItem -Path $spoolPath -ErrorAction SilentlyContinue
                    $spoolerResult.QueuedJobs = ($spoolFiles | Where-Object { $_.Extension -eq '.spl' }).Count
                    $spoolerResult.SpoolSize = ($spoolFiles | Measure-Object -Property Length -Sum).Sum
                }
            }
            catch {
                $Logger.WriteWarning("Could not access spool directory: $($_.Exception.Message)", $null, 'ClientSpooler')
            }
        }

        $isHealthy = $spoolerResult.ServiceFound -and $spoolerResult.ServiceRunning

        return @{
            IsSuccessful = $isHealthy
            Details = $spoolerResult
            Suggestions = if (-not $isHealthy) {
                @(
                    'Restart Print Spooler: net stop spooler && net start spooler',
                    'Set Spooler to Automatic startup if disabled',
                    'Check Windows Event Log for spooler errors',
                    'Run as Administrator for advanced spooler diagnostics'
                )
            } else { @() }
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "ClientSpooler" -Logger $Logger
}

function Start-ClientSideDiagnostic {
    <#
    .SYNOPSIS
        Performs comprehensive client-side printer diagnostics without requiring admin rights.
    #>
    [CmdletBinding()]
    param(
        [object]$Logger,
        [bool]$Detailed = $false,
        [bool]$ShowProgress = $true
    )

    $Logger.WriteInfo("Starting client-side printer diagnostic", @{
        Detailed = $Detailed
        User = $env:USERNAME
        Computer = $env:COMPUTERNAME
    }, 'ClientDiagnostic')

    # Create result object
    $result = New-DiagnosticResult -ServerName "Client: $env:COMPUTERNAME"

    # Create progress tracker
    $totalSteps = if ($Detailed) { 6 } else { 4 }
    $progress = New-ProgressTracker -TotalSteps $totalSteps -Activity "Client-Side Printer Diagnostic"

    try {
        # Step 1: Test Local Print Spooler
        $progress.UpdateProgress("Local Print Spooler", "Testing print spooler service")
        $spoolerResult = Test-ClientPrintSpooler -Logger $Logger
        $result.AddTest('LocalSpooler', $spoolerResult.IsSuccessful, $spoolerResult.Details, 0, 'System')

        # Step 2: Enumerate Client Printers
        $progress.UpdateProgress("Printer Enumeration", "Discovering available printers")
        $printersResult = Get-ClientSidePrinters -Logger $Logger
        $result.AddTest('ClientPrinters', $printersResult.IsSuccessful, $printersResult, 0, 'Printers')

        # Step 3: Test Default Printer
        $progress.UpdateProgress("Default Printer", "Testing default printer configuration")
        $defaultPrinterResult = Test-ClientDefaultPrinter -Logger $Logger
        $result.AddTest('DefaultPrinter', $defaultPrinterResult.IsSuccessful, $defaultPrinterResult, 0, 'Printers')

        # Step 4: Basic Connectivity Tests
        $progress.UpdateProgress("Connectivity Tests", "Testing printer connectivity")
        if ($printersResult.IsSuccessful -and $printersResult.Printers.Count -gt 0) {
            $connectivityResults = @()
            foreach ($printer in $printersResult.Printers) {
                $connResult = Test-ClientPrinterConnectivity -PrinterName $printer.Name -Logger $Logger
                $connectivityResults += $connResult
            }
            $result.AddTest('PrinterConnectivity', $true, $connectivityResults, 0, 'Connectivity')
        }

        if ($Detailed) {
            # Step 5: Print Queue Analysis
            $progress.UpdateProgress("Print Queue Analysis", "Analyzing print queues")
            $queueResult = Test-ClientPrintQueues -Logger $Logger
            $result.AddTest('PrintQueues', $queueResult.IsSuccessful, $queueResult, 0, 'Queues')

            # Step 6: Generate Comprehensive Suggestions
            $progress.UpdateProgress("Generating Report", "Creating troubleshooting suggestions")
            $suggestions = Generate-ClientTroubleshootingReport -Results $result -Logger $Logger
            $result.AddTest('TroubleshootingGuide', $true, $suggestions, 0, 'Guidance')
        }

        $progress.CompleteProgress()

        # Calculate final health
        $result.CalculateOverallHealth()
        $healthScore = $result.GetHealthScore()

        $passedTests = ($result.Summary.Values | Where-Object { $_ -eq $true }).Count
        $totalTests = $result.Summary.Count

        $Logger.WriteInfo("Client-side diagnostic completed", @{
            HealthScore = $healthScore
            TotalTests = $totalTests
            PassedTests = $passedTests
        }, 'ClientDiagnostic')

        return $result
    }
    catch {
        $Logger.WriteError("Client diagnostic failed", @{
            Error = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
        }, 'ClientDiagnostic')

        $progress.CompleteProgress()
        $result.AddError("Client diagnostic execution failed: $($_.Exception.Message)", 'System')
        return $result
    }
}

function Test-ClientDefaultPrinter {
    <#
    .SYNOPSIS
        Tests the default printer configuration and connectivity.
    #>
    [CmdletBinding()]
    param(
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Testing default printer configuration", $null, 'DefaultPrinter')

        $defaultPrinter = $null
        $method = 'Unknown'

        # Method 1: Try WMI
        try {
            $defaultPrinter = Get-WmiObject -Class Win32_Printer -Filter "Default=true" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($defaultPrinter) { $method = 'WMI' }
        }
        catch {
            $Logger.WriteDebug("WMI default printer detection failed: $($_.Exception.Message)", $null, 'DefaultPrinter')
        }

        # Method 2: Try Get-Printer
        if (-not $defaultPrinter -and (Get-Command -Name Get-Printer -ErrorAction SilentlyContinue)) {
            try {
                $defaultPrinter = Get-Printer | Where-Object { $_.Type -eq 'Local' } | Select-Object -First 1
                if ($defaultPrinter) { $method = 'Get-Printer' }
            }
            catch {
                $Logger.WriteDebug("Get-Printer default detection failed: $($_.Exception.Message)", $null, 'DefaultPrinter')
            }
        }

        # Method 3: Registry
        if (-not $defaultPrinter) {
            try {
                $regPath = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
                $deviceEntry = Get-ItemProperty -Path $regPath -Name "Device" -ErrorAction SilentlyContinue
                if ($deviceEntry -and $deviceEntry.Device) {
                    $printerName = ($deviceEntry.Device -split ',')[0]
                    $defaultPrinter = [PSCustomObject]@{ Name = $printerName }
                    $method = 'Registry'
                }
            }
            catch {
                $Logger.WriteDebug("Registry default printer detection failed: $($_.Exception.Message)", $null, 'DefaultPrinter')
            }
        }

        $result = @{
            HasDefaultPrinter = ($null -ne $defaultPrinter)
            PrinterName = if ($defaultPrinter) { $defaultPrinter.Name } else { 'None' }
            DetectionMethod = $method
            IsAccessible = $false
            Suggestions = @()
        }

        if ($defaultPrinter) {
            # Test connectivity to default printer
            try {
                $testResult = Test-ClientPrinterConnectivity -PrinterName $defaultPrinter.Name -Logger $Logger
                $result.IsAccessible = $testResult.IsSuccessful
            }
            catch {
                $Logger.WriteWarning("Default printer connectivity test failed: $($_.Exception.Message)", $null, 'DefaultPrinter')
            }
        } else {
            $result.Suggestions = @(
                'Set a default printer: Control Panel -> Devices and Printers -> Right-click printer -> Set as default',
                'Let Windows manage default printer: Settings -> Devices -> Printers -> Let Windows manage my default printer',
                'Install a printer if none are available'
            )
        }

        return @{
            IsSuccessful = $result.HasDefaultPrinter
            Details = $result
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "DefaultPrinter" -Logger $Logger
}

function Test-ClientPrinterConnectivity {
    <#
    .SYNOPSIS
        Tests connectivity to a specific printer from client perspective.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PrinterName,
        [object]$Logger
    )

    $operation = {
        $Logger.WriteDebug("Testing connectivity to printer: $PrinterName", $null, 'PrinterConnectivity')

        $connectivityResult = @{
            PrinterName = $PrinterName
            IsAccessible = $false
            ResponseTime = 0
            Method = 'Unknown'
            ErrorMessage = $null
        }

        $startTime = Get-Date

        try {
            # Method 1: Try .NET PrinterSettings
            Add-Type -AssemblyName System.Drawing
            $printerSettings = New-Object System.Drawing.Printing.PrinterSettings
            $printerSettings.PrinterName = $PrinterName

            if ($printerSettings.IsValid) {
                $connectivityResult.IsAccessible = $true
                $connectivityResult.Method = '.NET PrinterSettings'
            }
        }
        catch {
            $Logger.WriteDebug(".NET PrinterSettings test failed for $PrinterName`: $($_.Exception.Message)", $null, 'PrinterConnectivity')
        }

        # Method 2: Try Get-PrinterProperty (if available)
        if (-not $connectivityResult.IsAccessible -and (Get-Command -Name Get-PrinterProperty -ErrorAction SilentlyContinue)) {
            try {
                $properties = Get-PrinterProperty -PrinterName $PrinterName -ErrorAction Stop
                if ($properties) {
                    $connectivityResult.IsAccessible = $true
                    $connectivityResult.Method = 'Get-PrinterProperty'
                }
            }
            catch {
                $connectivityResult.ErrorMessage = $_.Exception.Message
                $Logger.WriteDebug("Get-PrinterProperty test failed for $PrinterName`: $($_.Exception.Message)", $null, 'PrinterConnectivity')
            }
        }

        $connectivityResult.ResponseTime = ((Get-Date) - $startTime).TotalMilliseconds

        return @{
            IsSuccessful = $connectivityResult.IsAccessible
            Details = $connectivityResult
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "PrinterConnectivity-$PrinterName" -Logger $Logger
}

function Test-ClientPrintQueues {
    <#
    .SYNOPSIS
        Analyzes print queues for stuck jobs and other issues.
    #>
    [CmdletBinding()]
    param(
        [object]$Logger
    )

    $operation = {
        $Logger.WriteInfo("Analyzing print queues", $null, 'PrintQueues')

        $queueAnalysis = @{
            TotalJobs = 0
            StuckJobs = 0
            LargeJobs = 0
            OldJobs = 0
            JobDetails = @()
            Suggestions = @()
        }

        try {
            # Try to get print jobs using Get-PrintJob (Windows 8+)
            if (Get-Command -Name Get-PrintJob -ErrorAction SilentlyContinue) {
                $printJobs = Get-PrintJob -ErrorAction SilentlyContinue

                foreach ($job in $printJobs) {
                    $jobAge = (Get-Date) - $job.SubmittedTime
                    $isStuck = ($job.JobStatus -eq 'Error' -or $job.JobStatus -eq 'Offline')
                    $isLarge = ($job.Size -gt 50MB)
                    $isOld = ($jobAge.TotalHours -gt 24)

                    $queueAnalysis.JobDetails += @{
                        Id = $job.Id
                        PrinterName = $job.PrinterName
                        Status = $job.JobStatus
                        Size = $job.Size
                        Age = $jobAge
                        IsStuck = $isStuck
                        IsLarge = $isLarge
                        IsOld = $isOld
                    }

                    if ($isStuck) { $queueAnalysis.StuckJobs++ }
                    if ($isLarge) { $queueAnalysis.LargeJobs++ }
                    if ($isOld) { $queueAnalysis.OldJobs++ }
                }

                $queueAnalysis.TotalJobs = $printJobs.Count
            }
        }
        catch {
            $Logger.WriteWarning("Print queue analysis failed: $($_.Exception.Message)", $null, 'PrintQueues')
        }

        # Generate suggestions based on findings
        if ($queueAnalysis.StuckJobs -gt 0) {
            $queueAnalysis.Suggestions += "Clear stuck print jobs using: Get-PrintJob | Where-Object {`$_.JobStatus -eq 'Error'} | Remove-PrintJob"
        }

        if ($queueAnalysis.LargeJobs -gt 0) {
            $queueAnalysis.Suggestions += "Large print jobs detected - consider splitting large documents"
        }

        if ($queueAnalysis.OldJobs -gt 0) {
            $queueAnalysis.Suggestions += "Old print jobs detected - clear completed jobs regularly"
        }

        return @{
            IsSuccessful = ($queueAnalysis.StuckJobs -eq 0)
            Analysis = $queueAnalysis
        }
    }

    return Invoke-SafeOperation -Operation $operation -OperationName "PrintQueues" -Logger $Logger
}

function Generate-ClientTroubleshootingReport {
    <#
    .SYNOPSIS
        Generates comprehensive troubleshooting suggestions based on diagnostic results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Results,
        [object]$Logger
    )

    $suggestions = @{
        CommonIssues = @(
            @{
                Issue = "No printers found"
                Cause = "No printers installed or accessible"
                Solutions = @(
                    "Install printer via Settings -> Devices -> Printers & scanners",
                    "Add network printer: \\server\printername or by IP address",
                    "Check if Print Spooler service is running",
                    "Verify network connectivity for network printers"
                )
            },
            @{
                Issue = "Printer shows offline"
                Cause = "Communication failure with printer"
                Solutions = @(
                    "Check printer power and connections",
                    "Test network connectivity (ping printer IP)",
                    "Restart Print Spooler service",
                    "Update printer drivers",
                    "Remove and re-add the printer"
                )
            },
            @{
                Issue = "Print jobs stuck in queue"
                Cause = "Print spooler or printer communication issues"
                Solutions = @(
                    "Clear print queue: Cancel all documents in printer queue",
                    "Restart Print Spooler: net stop spooler && net start spooler",
                    "Check printer status and connectivity",
                    "Verify sufficient disk space in spool directory"
                )
            }
        )
        QuickFixes = @(
            @{
                Command = 'net stop spooler && net start spooler'
                Description = 'Restart Print Spooler service'
                RequiresAdmin = $true
            },
            @{
                Command = 'Get-PrintJob | Remove-PrintJob'
                Description = 'Clear all print jobs from queue'
                RequiresAdmin = $false
            },
            @{
                Command = 'Get-Printer | Where-Object {$_.PrinterStatus -ne "Normal"}'
                Description = 'Find printers with issues'
                RequiresAdmin = $false
            }
        )
        GeneralTroubleshooting = @(
            "1. Check printer power and physical connections",
            "2. Verify network connectivity for network printers",
            "3. Update or reinstall printer drivers",
            "4. Clear print queue and restart Print Spooler",
            "5. Test with different document or application",
            "6. Check printer web interface (for network printers)",
            "7. Run Windows built-in printer troubleshooter"
        )
    }

    return $suggestions
}

function Start-ClientSidePrinterDiagnostic {
    <#
    .SYNOPSIS
        Main entry point for client-side printer diagnostics.
    #>
    [CmdletBinding()]
    param(
        [string]$LogPath = "$PSScriptRoot\Reports",
        [switch]$ExportResults,
        [switch]$ShowGui,
        [string]$ConfigPath = "$PSScriptRoot\PrintDiagConfig.json",
        [switch]$Detailed
    )

    # Create log directory
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }

    # Initialize logger
    $logger = New-DiagnosticLogger -LogDirectory $LogPath -WriteToConsole $true -WriteToFile $true

    $logger.WriteInfo("Starting client-side printer diagnostic session", @{
        SessionId = $script:SessionId
        Version = $script:DiagnosticVersion
        LogPath = $LogPath
        Detailed = $Detailed
        ExportResults = $ExportResults
        ShowGui = $ShowGui
    }, 'Main')

    try {
        # Run client diagnostic
        $result = Start-ClientSideDiagnostic -Logger $logger -Detailed $Detailed -ShowProgress $true

        # Display results to console
        Show-ClientDiagnosticResults -Result $result -Logger $logger

        # Export results if requested
        if ($ExportResults) {
            Export-ClientDiagnosticResults -Result $result -LogPath $LogPath -Logger $logger
        }

        # Show GUI if requested
        if ($ShowGui) {
            Show-ClientDiagnosticGui -Result $result -Logger $logger
        }

        return $result
    }
    catch {
        $logger.WriteError("Client diagnostic session failed", @{
            Error = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
        }, 'Main')
        throw
    }
}

function Show-ClientDiagnosticResults {
    <#
    .SYNOPSIS
        Displays client diagnostic results in formatted console output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,
        [object]$Logger
    )

    Write-Host ""
    Write-Host "CLIENT-SIDE PRINTER DIAGNOSTIC RESULTS" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Cyan

    # Display test results by category
    $categories = @{
        'System' = 'System Tests'
        'Printers' = 'Printer Tests'
        'Connectivity' = 'Connectivity Tests'
        'Queues' = 'Queue Tests'
        'Guidance' = 'Troubleshooting'
    }

    foreach ($category in $categories.Keys) {
        $tests = $Result.Details | Where-Object { $_.Category -eq $category }
        if ($tests.Count -gt 0) {
            Write-Host ""
            Write-Host "$($categories[$category]):" -ForegroundColor Yellow
            Write-Host ("-" * 40) -ForegroundColor Gray

            foreach ($test in $tests) {
                $status = if ($test.IsSuccessful) { "[PASS]" } else { "[FAIL]" }
                $color = if ($test.IsSuccessful) { "Green" } else { "Red" }
                $duration = if ($test.Duration -gt 0) { " ($($test.Duration)ms)" } else { "" }

                Write-Host "  $($test.TestName.PadRight(30)) $status$duration" -ForegroundColor $color

                # Show detailed printer information
                if ($test.TestName -eq 'ClientPrinters' -and $test.IsSuccessful -and $test.Result.Printers) {
                    Write-Host ""
                    Write-Host "    Discovered Printers:" -ForegroundColor Cyan
                    foreach ($printer in $test.Result.Printers) {
                        $statusIcon = if ($printer.IsHealthy) { "[OK]" } else { "[!]" }
                        $statusColor = if ($printer.IsHealthy) { "Green" } else { "Red" }

                        Write-Host "      $statusIcon $($printer.Name)" -ForegroundColor $statusColor
                        Write-Host "        Status: $($printer.Status)" -ForegroundColor Gray
                        Write-Host "        Port: $($printer.PortName) ($($printer.PortType))" -ForegroundColor Gray
                        Write-Host "        Driver: $($printer.DriverName)" -ForegroundColor Gray
                        if ($printer.Firmware -and $printer.Firmware -ne 'Unknown') {
                            Write-Host "        Firmware: $($printer.Firmware)" -ForegroundColor Gray
                        }
                        if ($printer.Network) {
                            Write-Host "        Network Printer: Yes" -ForegroundColor Cyan
                        }
                        if ($printer.Default) {
                            Write-Host "        Default Printer: Yes" -ForegroundColor Green
                        }

                        # Show port information
                        if ($printer.PortDescription -and $printer.PortDescription -ne 'Unknown port type') {
                            Write-Host "        Port Info: $($printer.PortDescription)" -ForegroundColor Yellow
                        }

                        # Show error suggestions if any
                        if (-not $printer.IsHealthy -and $printer.ErrorSuggestions.Count -gt 0) {
                            Write-Host "        Suggestions:" -ForegroundColor Yellow
                            foreach ($suggestion in $printer.ErrorSuggestions) {
                                if ($suggestion.Type -eq 'Offline') {
                                    Write-Host "          • Printer is offline - check power and connectivity" -ForegroundColor Red
                                }
                                foreach ($solution in $suggestion.Solutions | Select-Object -First 2) {
                                    Write-Host "          -> $solution" -ForegroundColor Gray
                                }
                            }
                        }
                        Write-Host ""
                    }

                    # Show statistics
                    if ($test.Result.Statistics) {
                        $stats = $test.Result.Statistics
                        Write-Host "    Summary:" -ForegroundColor Cyan
                        Write-Host "      Total Printers: $($stats.TotalPrinters)" -ForegroundColor Gray
                        Write-Host "      Online: $($stats.OnlinePrinters)" -ForegroundColor Green
                        Write-Host "      Offline: $($stats.OfflinePrinters)" -ForegroundColor Red
                        Write-Host "      Network Printers: $($stats.NetworkPrinters)" -ForegroundColor Cyan
                        if ($stats.DefaultPrinter) {
                            Write-Host "      Default: $($stats.DefaultPrinter)" -ForegroundColor Yellow
                        }
                    }
                    Write-Host ""
                }
            }
        }
    }

    # Show port reference information
    Write-Host ""
    Write-Host "COMMON PRINTING PORTS REFERENCE:" -ForegroundColor Yellow
    Write-Host ("-" * 40) -ForegroundColor Gray
    $portRef = Get-PrintingPortReference
    $commonPorts = @(9100, 515, 631, 80, 443, 445, 135)
    foreach ($port in $commonPorts) {
        if ($portRef[$port]) {
            $info = $portRef[$port]
            Write-Host "  Port $port - $($info.Protocol): $($info.Description)" -ForegroundColor Cyan
        }
    }

    # Overall health summary
    Write-Host ""
    Write-Host "=" * 50 -ForegroundColor Cyan
    Write-Host "OVERALL HEALTH SUMMARY" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Cyan

    $healthScore = $Result.GetHealthScore()
    $healthColor = if ($healthScore -gt 80) { "Green" } elseif ($healthScore -gt 60) { "Yellow" } else { "Red" }
    $healthStatus = if ($Result.OverallHealth) { "HEALTHY" } else { "ISSUES DETECTED" }

    Write-Host "Client: $($Result.ServerName)" -ForegroundColor Gray
    Write-Host "Health Score: $healthScore%" -ForegroundColor $healthColor
    Write-Host "Overall Status: $healthStatus" -ForegroundColor $healthColor
    Write-Host ""

    if ($Result.Errors.Count -gt 0) {
        Write-Host "ERRORS ($($Result.Errors.Count)):" -ForegroundColor Red
        Write-Host ("-" * 40) -ForegroundColor Gray
        foreach ($error in $Result.Errors) {
            Write-Host "  • $($error.Message)" -ForegroundColor Red
        }
        Write-Host ""
    }

    if ($Result.Warnings.Count -gt 0) {
        Write-Host "WARNINGS ($($Result.Warnings.Count)):" -ForegroundColor Yellow
        Write-Host ("-" * 40) -ForegroundColor Gray
        foreach ($warning in $Result.Warnings) {
            Write-Host "  • $($warning.Message)" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    Write-Host "=" * 50 -ForegroundColor Cyan
    Write-Host "Log files location: $(if ($Result.SystemInfo.LogPath) { $Result.SystemInfo.LogPath } else { 'N/A' })" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Client-side diagnostic completed successfully!" -ForegroundColor Green
    Write-Host "Thank you for using Enhanced Print Server Diagnostic Tool v$script:DiagnosticVersion" -ForegroundColor Cyan
    Write-Host ""
}

function Export-ClientDiagnosticResults {
    <#
    .SYNOPSIS
        Exports client diagnostic results to multiple formats.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,
        [Parameter(Mandatory)]
        [string]$LogPath,
        [object]$Logger
    )

    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $baseFileName = "ClientPrinterDiagnostic_$($env:COMPUTERNAME)_$($Result.SessionId)"

        # Export HTML report
        $htmlPath = Join-Path $LogPath "$baseFileName.html"
        Export-ClientHtmlReport -Result $Result -OutputPath $htmlPath -Logger $Logger

        # Export JSON data
        $jsonPath = Join-Path $LogPath "$baseFileName.json"
        $Result | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8

        $Logger.WriteInfo("Client diagnostic results exported", @{
            HtmlReport = $htmlPath
            JsonData = $jsonPath
        }, 'Export')

        # Try to open HTML report
        try {
            Start-Process $htmlPath
            $Logger.WriteInfo("HTML report opened automatically", @{ Path = $htmlPath }, 'Export')
        }
        catch {
            $Logger.WriteWarning("Could not open HTML report automatically", @{ Path = $htmlPath }, 'Export')
        }
    }
    catch {
        $Logger.WriteError("Failed to export client diagnostic results", @{
            Error = $_.Exception.Message
        }, 'Export')
    }
}

function Export-ClientHtmlReport {
    <#
    .SYNOPSIS
        Generates an HTML report for client-side diagnostics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [object]$Logger
    )

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Client Printer Diagnostic Report - $($Result.ServerName)</title>
    <style>
        :root {
            --primary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --info: #3498db;
            --light: #ecf0f1;
            --dark: #34495e;
        }

        * { box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }

        .header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--dark) 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5rem;
            font-weight: 300;
        }

        .header .subtitle {
            opacity: 0.9;
            font-size: 1.1rem;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: var(--light);
        }

        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }

        .summary-card h3 {
            margin: 0 0 10px 0;
            color: var(--dark);
        }

        .summary-card .value {
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0;
        }

        .success { color: var(--success); }
        .warning { color: var(--warning); }
        .danger { color: var(--danger); }
        .info { color: var(--info); }

        .content {
            padding: 30px;
        }

        .printer-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .printer-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
            border-left: 4px solid var(--primary);
        }

        .printer-card.healthy {
            border-left-color: var(--success);
        }

        .printer-card.unhealthy {
            border-left-color: var(--danger);
        }

        .printer-card-header {
            padding: 20px;
            background: var(--light);
        }

        .printer-card-body {
            padding: 20px;
        }

        .printer-name {
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .printer-status {
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }

        .status-healthy {
            background: var(--success);
            color: white;
        }

        .status-unhealthy {
            background: var(--danger);
            color: white;
        }

        .printer-details {
            margin-top: 15px;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            padding-bottom: 5px;
            border-bottom: 1px solid #eee;
        }

        .detail-label {
            font-weight: bold;
            color: var(--dark);
        }

        .detail-value {
            color: #666;
        }

        .suggestions {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }

        .suggestions h4 {
            margin: 0 0 10px 0;
            color: var(--warning);
        }

        .suggestions ul {
            margin: 0;
            padding-left: 20px;
        }

        .port-reference {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            margin-top: 30px;
        }

        .port-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        .port-table th,
        .port-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        .port-table th {
            background: var(--primary);
            color: white;
        }

        .footer {
            background: var(--dark);
            color: white;
            padding: 20px;
            text-align: center;
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Client Printer Diagnostic Report</h1>
            <div class="subtitle">$($Result.ServerName) - Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Health Score</h3>
                <div class="value $(if ($Result.GetHealthScore() -gt 80) { 'success' } elseif ($Result.GetHealthScore() -gt 60) { 'warning' } else { 'danger' })">$($Result.GetHealthScore())%</div>
            </div>
            <div class="summary-card">
                <h3>Total Tests</h3>
                <div class="value info">$($Result.Summary.Count)</div>
            </div>
            <div class="summary-card">
                <h3>Passed</h3>
                <div class="value success">$(($Result.Summary.Values | Where-Object { $_ -eq $true }).Count)</div>
            </div>
            <div class="summary-card">
                <h3>Issues</h3>
                <div class="value danger">$($Result.Errors.Count + $Result.Warnings.Count)</div>
            </div>
        </div>

        <div class="content">
"@

    # Add printer information if available
    $printerTest = $Result.Details | Where-Object { $_.TestName -eq 'ClientPrinters' } | Select-Object -First 1
    if ($printerTest -and $printerTest.Result.Printers) {
        $html += @"
            <h2>Discovered Printers</h2>
            <div class="printer-grid">
"@

        foreach ($printer in $printerTest.Result.Printers) {
            $healthClass = if ($printer.IsHealthy) { 'healthy' } else { 'unhealthy' }
            $statusClass = if ($printer.IsHealthy) { 'status-healthy' } else { 'status-unhealthy' }

            $html += @"
                <div class="printer-card $healthClass">
                    <div class="printer-card-header">
                        <div class="printer-name">$($printer.Name)</div>
                        <span class="printer-status $statusClass">$($printer.Status)</span>
                    </div>
                    <div class="printer-card-body">
                        <div class="printer-details">
                            <div class="detail-row">
                                <span class="detail-label">Port:</span>
                                <span class="detail-value">$($printer.PortName) ($($printer.PortType))</span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label">Driver:</span>
                                <span class="detail-value">$($printer.DriverName)</span>
                            </div>
"@

            if ($printer.Firmware -and $printer.Firmware -ne 'Unknown') {
                $html += @"
                            <div class="detail-row">
                                <span class="detail-label">Firmware:</span>
                                <span class="detail-value">$($printer.Firmware)</span>
                            </div>
"@
            }

            if ($printer.Network) {
                $html += @"
                            <div class="detail-row">
                                <span class="detail-label">Type:</span>
                                <span class="detail-value">Network Printer</span>
                            </div>
"@
            }

            if ($printer.Default) {
                $html += @"
                            <div class="detail-row">
                                <span class="detail-label">Default:</span>
                                <span class="detail-value">Yes</span>
                            </div>
"@
            }

            # Add troubleshooting suggestions for problematic printers
            if (-not $printer.IsHealthy -and $printer.ErrorSuggestions.Count -gt 0) {
                $html += @"
                        </div>
                        <div class="suggestions">
                            <h4>Troubleshooting Suggestions:</h4>
                            <ul>
"@
                foreach ($suggestion in $printer.ErrorSuggestions) {
                    foreach ($solution in $suggestion.Solutions | Select-Object -First 3) {
                        $html += "<li>$solution</li>"
                    }
                }
                $html += @"
                            </ul>
                        </div>
"@
            } else {
                $html += "</div>"
            }

            $html += @"
                    </div>
                </div>
"@
        }

        $html += "</div>"
    }

    # Add port reference
    $html += @"
            <div class="port-reference">
                <h2>Common Printing Ports Reference</h2>
                <p>Understanding network ports used for printing can help with troubleshooting connectivity issues.</p>
                <table class="port-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Description</th>
                            <th>Usage</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    $portRef = Get-PrintingPortReference
    $displayPorts = @(9100, 515, 631, 80, 443, 161, 445, 135, 5985)
    foreach ($port in $displayPorts) {
        if ($portRef[$port]) {
            $info = $portRef[$port]
            $html += @"
                        <tr>
                            <td><strong>$port</strong></td>
                            <td>$($info.Protocol)</td>
                            <td>$($info.Description)</td>
                            <td>$($info.Usage)</td>
                        </tr>
"@
        }
    }

    $html += @"
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            <p>Enhanced Print Server Diagnostic Tool v$script:DiagnosticVersion</p>
            <p>Client-Side Printer Analysis - Session: $($Result.SessionId)</p>
        </div>
    </div>
</body>
</html>
"@

    # Write HTML to file
    $html | Out-File -FilePath $OutputPath -Encoding UTF8

    $Logger.WriteInfo("Client HTML report generated successfully", @{
        Path = $OutputPath
        Size = (Get-Item $OutputPath).Length
    }, 'Export')
}

function Show-ClientDiagnosticGui {
    <#
    .SYNOPSIS
        Shows client diagnostic results in a GUI window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,
        [object]$Logger
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        # Create main form
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Client Printer Diagnostic Results - $($Result.ServerName)"
        $form.Size = New-Object System.Drawing.Size(900, 700)
        $form.StartPosition = "CenterScreen"
        $form.BackColor = [System.Drawing.Color]::White

        # Create tab control
        $tabControl = New-Object System.Windows.Forms.TabControl
        $tabControl.Dock = "Fill"
        $form.Controls.Add($tabControl)

        # Summary tab
        $summaryTab = New-Object System.Windows.Forms.TabPage
        $summaryTab.Text = "Summary"
        $tabControl.Controls.Add($summaryTab)

        $summaryTextBox = New-Object System.Windows.Forms.RichTextBox
        $summaryTextBox.Dock = "Fill"
        $summaryTextBox.ReadOnly = $true
        $summaryTextBox.Font = New-Object System.Drawing.Font("Consolas", 10)

        $summaryText = @"
CLIENT PRINTER DIAGNOSTIC SUMMARY
==================================
Computer: $($Result.ServerName)
Session: $($Result.SessionId)
Health Score: $($Result.GetHealthScore())%
Overall Status: $(if ($Result.OverallHealth) { 'HEALTHY' } else { 'ISSUES DETECTED' })

TEST RESULTS:
$(foreach ($test in $Result.Details) { "- $($test.TestName): $(if ($test.IsSuccessful) { 'PASS' } else { 'FAIL' })" }) -join "`n")"

DISCOVERED PRINTERS:
"@

        $printerTest = $Result.Details | Where-Object { $_.TestName -eq 'ClientPrinters' } | Select-Object -First 1
        if ($printerTest -and $printerTest.Result.Printers) {
            foreach ($printer in $printerTest.Result.Printers) {
                $summaryText += @"

• $($printer.Name)
  Status: $($printer.Status)
  Port: $($printer.PortName) ($($printer.PortType))
  Driver: $($printer.DriverName)
"@
                if ($printer.Firmware -and $printer.Firmware -ne 'Unknown') {
                    $summaryText += "`n  Firmware: $($printer.Firmware)"
                }
                if ($printer.Network) {
                    $summaryText += "`n  Type: Network Printer"
                }
                if ($printer.Default) {
                    $summaryText += "`n  Default: Yes"
                }
            }
        }

        $summaryTextBox.Text = $summaryText
        $summaryTab.Controls.Add($summaryTextBox)

        # Printers tab (if available)
        if ($printerTest -and $printerTest.Result.Printers) {
            $printersTab = New-Object System.Windows.Forms.TabPage
            $printersTab.Text = "Printers"
            $tabControl.Controls.Add($printersTab)

            $printersListView = New-Object System.Windows.Forms.ListView
            $printersListView.Dock = "Fill"
            $printersListView.View = "Details"
            $printersListView.FullRowSelect = $true
            $printersListView.GridLines = $true

            # Add columns
            $printersListView.Columns.Add("Name", 200)
            $printersListView.Columns.Add("Status", 120)
            $printersListView.Columns.Add("Port", 150)
            $printersListView.Columns.Add("Driver", 200)
            $printersListView.Columns.Add("Type", 100)

            # Add printer items
            foreach ($printer in $printerTest.Result.Printers) {
                $item = $printersListView.Items.Add($printer.Name)
                $item.SubItems.Add($printer.Status)
                $item.SubItems.Add("$($printer.PortName) ($($printer.PortType))")
                $item.SubItems.Add($printer.DriverName)
                $item.SubItems.Add($(if ($printer.Network) { 'Network' } else { 'Local' }))

                if ($printer.IsHealthy) {
                    $item.BackColor = [System.Drawing.Color]::LightGreen
                } else {
                    $item.BackColor = [System.Drawing.Color]::LightCoral
                }
            }

            $printersTab.Controls.Add($printersListView)
        }

        # Port Reference tab
        $portTab = New-Object System.Windows.Forms.TabPage
        $portTab.Text = "Port Reference"
        $tabControl.Controls.Add($portTab)

        $portListView = New-Object System.Windows.Forms.ListView
        $portListView.Dock = "Fill"
        $portListView.View = "Details"
        $portListView.FullRowSelect = $true
        $portListView.GridLines = $true

        $portListView.Columns.Add("Port", 80)
        $portListView.Columns.Add("Protocol", 150)
        $portListView.Columns.Add("Description", 300)
        $portListView.Columns.Add("Usage", 250)

        $portRef = Get-PrintingPortReference
        $displayPorts = @(9100, 515, 631, 80, 443, 161, 445, 135, 5985, 5986)
        foreach ($port in $displayPorts) {
            if ($portRef[$port]) {
                $info = $portRef[$port]
                $item = $portListView.Items.Add($port.ToString())
                $item.SubItems.Add($info.Protocol)
                $item.SubItems.Add($info.Description)
                $item.SubItems.Add($info.Usage)
            }
        }

        $portTab.Controls.Add($portListView)

        # Show the form
        $Logger.WriteInfo("Displaying client diagnostic GUI", $null, 'GUI')
        $form.ShowDialog()
    }
    catch {
        $Logger.WriteError("Failed to show client diagnostic GUI", @{
            Error = $_.Exception.Message
        }, 'GUI')
        Write-Warning "Could not display GUI: $($_.Exception.Message)"
    }
}

# =============================================================================
# MAIN EXECUTION BLOCK
# =============================================================================

try {
    Write-Host ""
    Write-Host "Enhanced Print Server Diagnostic Tool v$script:DiagnosticVersion" -ForegroundColor Cyan
    Write-Host "Enterprise-Grade Print Server Health Assessment" -ForegroundColor Cyan
    Write-Host "Session ID: $script:SessionId" -ForegroundColor Gray
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""

    # Display configuration summary
    Write-Host "Configuration Summary:" -ForegroundColor Yellow
    if ($Client) {
        Write-Host "  Mode: Client-side printer testing (no admin privileges required)" -ForegroundColor Cyan
        Write-Host "  Target: Local and accessible network printers" -ForegroundColor Gray
    } else {
        Write-Host "  Target Server: $ServerFqdn" -ForegroundColor Gray
        Write-Host "  Port Scan: $($Ports.Count + $ExtraPorts.Count) ports" -ForegroundColor Gray
        Write-Host "  Event Count: $EventCount events" -ForegroundColor Gray
    }
    Write-Host "  Log Path: $LogPath" -ForegroundColor Gray
    Write-Host "  Detailed Mode: $Detailed" -ForegroundColor Gray
    if (-not $Client) {
        Write-Host "  Parallel Processing: $Parallel" -ForegroundColor Gray
        Write-Host "  Max Threads: $MaxThreads" -ForegroundColor Gray
    }
    Write-Host ""

    # Run the appropriate diagnostic based on mode
    if ($Client) {
        $clientParams = @{
            LogPath = $LogPath
            ConfigPath = $ConfigPath
        }
        if ($ExportResults) { $clientParams['ExportResults'] = $true }
        if ($ShowGui) { $clientParams['ShowGui'] = $true }
        if ($Detailed) { $clientParams['Detailed'] = $true }
        $diagnosticResult = Start-ClientSidePrinterDiagnostic @clientParams
    } else {
        $diagnosticResult = Start-ComprehensivePrintServerDiagnostic -ServerFqdn $ServerFqdn -Ports $Ports -ExtraPorts $ExtraPorts -EventCount $EventCount -LogPath $LogPath -ExportResults $ExportResults -ShowGui $ShowGui -ConfigPath $ConfigPath -Detailed $Detailed -Parallel $Parallel -MaxThreads $MaxThreads
    }

    # Display comprehensive summary
    Show-DiagnosticSummary -DiagnosticResult $diagnosticResult

    # Final status
    Write-Host "Log files location: $LogPath" -ForegroundColor Gray

    if ($ExportResults) {
        Write-Host "Comprehensive reports exported to: $LogPath" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Diagnostic completed successfully!" -ForegroundColor Green
    Write-Host "Thank you for using Enhanced Print Server Diagnostic Tool v$script:DiagnosticVersion" -ForegroundColor Cyan
    Write-Host ""

    # Return the result for further processing if needed
    return $diagnosticResult
}
catch {
    Write-Host ""
    Write-Host "FATAL ERROR during diagnostic execution:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    Write-Host ""
    Write-Host "Please check the log files at: $LogPath" -ForegroundColor Yellow
    Write-Host "Session ID for reference: $script:SessionId" -ForegroundColor Yellow

    exit 1
}