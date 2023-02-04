# comments to yossis@protonmail.com
# Detection via event ID 4769 (TGS) with Error code 0x1f + TGT Anomalies. Useful when coming to a site recently After a krbtgt double-reset.
# NOTE: Run this script AFTER resetting the krbtgt password TWICE (for more info, read: https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51)
# Requires Event Log Redears or equivalent (preferrably - run elevated on the PDC/one of the DCs, for better Performance and continued operation of the monitoring process)

$ErrorActionPreference = "SilentlyContinue";
$version = "1.0.1";

$Logo = @"

_____       _     _              _____ _      _        _     _____ _               _    
|  __ \     | |   | |            |_   _(_)    | |      | |   /  __ \ |             | |   
| |  \/ ___ | | __| | ___ _ __     | |  _  ___| | _____| |_  | /  \/ |__   ___  ___| | __
| | __ / _ \| |/ _` |/ _ \ '_ \    | | | |/ __| |/ / _ \ __| | |   | '_ \ / _ \/ __| |/ /
| |_\ \ (_) | | (_| |  __/ | | |   | | | | (__|   <  __/ |_  | \__/\ | | |  __/ (__|   < 
 \____/\___/|_|\__,_|\___|_| |_|   \_/ |_|\___|_|\_\___|\__|  \____/_| |_|\___|\___|_|\_\
                                                                                         
 Checks for potential golden tickets by monitoring for integrity failures in new TGS requests Post-Krbtgt Reset
 by 10Root Cyber Security (comments to yossis@protonmail.com) <Version: $version>

"@

$Logo;

$Transcript = ".\Monitor-Potential-GoldenTicket-Comeback_$($ENV:USERDOMAIN)_$(Get-Date -Format ddMMyyyyHHmmss).txt";
Start-Transcript $Transcript;

# Set Date to match the last krbtgt reset
[datetime]$StartDate = [datetime]::FromFileTime($(Get-ADUser krbtgt -Properties pwdlastset).pwdlastset) #New-Object "System.DateTime" -ArgumentList (Get-Date).Year, (Get-Date).Month, (Get-Date).Day;

Write-Host "[x] Checking events from $StartDate onwards (last KRBTGT password reset)." -ForegroundColor Yellow;
$DCs = Get-ADDomainController -Filter * | select -ExpandProperty name;

$regex = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'; # for IPv4 matches

While ($true) {

$Events = @();
$DCs | foreach {
	$DC = $_;
        write-host "[x] Fetching TGS events from $DC..." -ForegroundColor Cyan;
        $Events += Get-WinEvent -FilterHashtable @{logname='Security';id=4769;StartTime=$StartDate} -ComputerName $DC;
	if (!$?) {"[x] $(Get-Date): $($error[0].Exception.Message) <DC: $DC>"}
    }

Write-Host "[x] $(Get-Date): Collected $($events.count) Events." -ForegroundColor green;

$FailedAuditTGS = $Events | where keywordsDisplayNames -eq "Audit Failure" #keywords="-9218868437227405312"

if ($FailedAuditTGS) {
$FailedAuditTGS | foreach { 
    $Event = $_;
    if (([xml]($Event.ToXml())).event.eventdata.data.'#text'[8] -eq "0x1f") # Status/Error Code = Integrity check on decrypted field failed
        {
            Write-Host "`n[!] Found suspicious TGS!" -ForegroundColor Red;
            $IPAddress = ([xml]($Event.ToXml())).event.eventdata.data.'#text'[6];
            $ComputerName = (Resolve-DnsName ($IPAddress | sls -Pattern $regex).Matches.Value).nameHost;
            Write-Host "IP Address: $IPAddress (ComputerName: $ComputerName)" -ForegroundColor Yellow;
            Write-Host "Time Created: $($Event.TimeCreated)" -ForegroundColor Yellow;
            Write-Host "TargetUserName: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[0])";
            Write-Host "TargetDomainName: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[1])";
            Write-Host "ServiceName: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[2])";
            Write-Host "ServiceSID: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[3])";
            Write-Host "TicketOptions: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[4])";
            Write-Host "TicketEncryptionType: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[5])";
            Write-Host "Port: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[7])";
            Write-Host "Status/Error Code: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[8])";
            Write-Host "Logon GUID: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[9])";
            Write-Host "TransmittedServices: $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[10])`n";
        }
    }
}

Write-Host "[x] Finished looking for suspicious TGS events on all DCs. WAITING FOR NEXT CHECK/LOOP." -ForegroundColor Magenta;
Write-Host "[!] To quit, Press CTRL+C, and then Type " -ForegroundColor Yellow -NoNewline; Write-Host  "Stop-Transcript" -ForegroundColor Cyan -NoNewline; Write-Host " and press " -ForegroundColor Yellow -NoNewline; Write-Host "ENTER." -ForegroundColor Cyan;

# free up memory
Clear-Variable Events; [gc]::Collect();

# loop every 5 minutes
Sleep -Seconds 300;
}