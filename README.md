# 🖨️ Print Server Diagnostic Tool

**A comprehensive PowerShell diagnostic tool for Windows print servers and client-side printer testing.**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://github.com/PowerShell/PowerShell)
[![Windows](https://img.shields.io/badge/Windows-10%2B%20%7C%20Server%202016%2B-green)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🚀 Quick Start

### Option 1: Client-Side Testing (No Admin Required)
```powershell
# Test your local printers and print system
.\PrintServer-Diagnostic.ps1 -Client
```

### Option 2: Print Server Analysis (Admin Required)
```powershell
# Test a print server in your network
.\PrintServer-Diagnostic.ps1 -ServerFqdn "your-printserver.domain.com"
```

### Option 3: Full Analysis with Reports
```powershell
# Get detailed reports with visual dashboard
.\PrintServer-Diagnostic.ps1 -Client -ExportResults -Detailed
```

## ✨ Features

### 🖥️ **Client Mode** (No Admin Rights Required)
- **Local Printer Detection** - Discovers all accessible printers
- **Print Spooler Health** - Tests local print service
- **Default Printer Validation** - Verifies default printer setup
- **Driver Analysis** - Checks printer driver status
- **Port Information** - Identifies printer connections and protocols
- **Error Suggestions** - Provides actionable troubleshooting steps

### 🖧 **Server Mode** (Network Print Server Analysis)
- **Network Connectivity** - DNS, ping, and port scanning
- **Print Services** - Spooler, sharing, and queue analysis
- **CIM/WMI Management** - Remote server health monitoring
- **Event Log Analysis** - Recent printing errors and warnings
- **Performance Metrics** - Response times and health scores

### 📊 **Professional Reporting**
- **Interactive HTML Dashboard** - Visual reports with charts
- **JSON Data Export** - Structured data for automation
- **Real-time Console Output** - Immediate feedback
- **Windows Forms GUI** - User-friendly interface (use `-ShowGui`)

## 📋 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **PowerShell** | 5.1 | 7.x |
| **Windows** | 10 / Server 2016 | 11 / Server 2022 |
| **Memory** | 2GB | 4GB+ |
| **Network** | Basic connectivity | Gigabit for large environments |

## 🛠️ Installation

### Download & Run
1. Download `PrintServer-Diagnostic.ps1`
2. Open PowerShell as Administrator (for server mode) or regular user (for client mode)
3. Navigate to the script directory
4. Run the script with your preferred options

### Set Execution Policy (if needed)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 📖 Usage Examples

### Basic Client Testing
```powershell
# Quick printer health check
.\PrintServer-Diagnostic.ps1 -Client

# Detailed analysis with visual reports
.\PrintServer-Diagnostic.ps1 -Client -Detailed -ExportResults

# Include GUI interface
.\PrintServer-Diagnostic.ps1 -Client -ShowGui -ExportResults
```

### Print Server Analysis
```powershell
# Standard server diagnostic
.\PrintServer-Diagnostic.ps1 -ServerFqdn "printserver.company.com"

# Comprehensive analysis with custom ports
.\PrintServer-Diagnostic.ps1 -ServerFqdn "printserver.company.com" -Detailed -ExtraPorts 9100,515,631 -ExportResults

# High-performance parallel testing
.\PrintServer-Diagnostic.ps1 -ServerFqdn "printserver.company.com" -Parallel -MaxThreads 20 -ExportResults
```

### Bulk Server Testing
```powershell
# Test multiple servers
@("server1.domain.com", "server2.domain.com") | ForEach-Object {
    .\PrintServer-Diagnostic.ps1 -ServerFqdn $_ -ExportResults
}

# Active Directory integration
Get-ADComputer -Filter "Name -like '*print*'" | ForEach-Object {
    .\PrintServer-Diagnostic.ps1 -ServerFqdn $_.DNSHostName -Detailed
}
```

## 📊 Report Outputs

### Console Output
- Real-time progress updates
- Color-coded test results
- Performance metrics
- Health score summary

### HTML Reports
- Interactive dashboard with charts
- Expandable test details
- Printer inventory with capabilities
- Port reference guide
- Troubleshooting recommendations

### JSON Export
- Structured test results
- Performance data
- Error details
- Integration-ready format

## 🔧 Configuration

### Command Line Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-Client` | Client-side testing mode | `-Client` |
| `-ServerFqdn` | Target print server | `-ServerFqdn "server.domain.com"` |
| `-ExportResults` | Generate HTML/JSON reports | `-ExportResults` |
| `-ShowGui` | Display Windows Forms interface | `-ShowGui` |
| `-Detailed` | Extended analysis mode | `-Detailed` |
| `-Parallel` | Enable multi-threading | `-Parallel` |
| `-MaxThreads` | Thread limit (1-50) | `-MaxThreads 15` |
| `-EventCount` | Events to retrieve (1-1000) | `-EventCount 100` |
| `-LogPath` | Report output directory | `-LogPath "C:\Reports"` |

### JSON Configuration
Create `PrintDiagConfig.json` for advanced settings:

```json
{
  "logging": {
    "level": "INFO",
    "enableConsole": true,
    "enableFile": true
  },
  "timeouts": {
    "general": 30,
    "ping": 5,
    "port": 5000
  },
  "parallel": {
    "enabled": true,
    "maxThreads": 10
  }
}
```

## 🩺 Troubleshooting

### Common Issues

**Execution Policy Error**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Access Denied**
- Run PowerShell as Administrator for server mode
- Use `-Client` parameter for non-admin testing
- Check firewall settings for remote connections

**No Printers Found**
- Verify printer installation
- Check Print Spooler service status
- Test with `-Detailed` for more information

**Connection Timeout**
- Verify server name/IP address
- Check network connectivity
- Test with reduced thread count: `-MaxThreads 5`

### Getting Help
```powershell
# Built-in help
Get-Help .\PrintServer-Diagnostic.ps1 -Full

# Parameter details
Get-Help .\PrintServer-Diagnostic.ps1 -Parameter ServerFqdn

# Usage examples
Get-Help .\PrintServer-Diagnostic.ps1 -Examples
```

## 🚀 Advanced Features

### Performance Optimization
- **Parallel Processing** - Multi-threaded operations for speed
- **Smart Caching** - Reduced redundant operations
- **Timeout Management** - Configurable timeouts prevent hanging

### Security
- **No Hardcoded Credentials** - Uses current user context
- **Input Validation** - Prevents injection attacks
- **Audit Logging** - Comprehensive activity tracking
- **Least Privilege** - Works with standard user rights

### Compatibility
- **Cross-Version Support** - PowerShell 5.1 through 7.x
- **Zero Dependencies** - Pure PowerShell implementation
- **Universal Windows** - Desktop and Server editions

## 📁 File Structure

```
Reports/
├── ClientPrinterDiagnostic_[Computer]_[SessionId].html
├── ClientPrinterDiagnostic_[Computer]_[SessionId].json
├── PrintServerDiag_[DateTime].log
└── PrintDiagConfig.json (optional)
```

## 🏆 Why This Tool?

✅ **No External Dependencies** - Pure PowerShell, runs anywhere
✅ **Dual Mode Operation** - Client and server testing in one tool
✅ **Professional Reports** - Executive-ready HTML dashboards
✅ **Enterprise Ready** - Handles large environments with parallel processing
✅ **User Friendly** - Works for both IT pros and end users
✅ **Comprehensive** - Tests everything from network to applications

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

---

**Print Server Diagnostic Tool** - Making printer troubleshooting simple and comprehensive.
