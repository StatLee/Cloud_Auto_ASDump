<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio
	 Created on:   	2018/8/3 21:30
	 Created by:   	statli
	 Organization: 	Tencent
	 Filename: Dump文件自动分析
	===========================================================================
#>
function Get-AutoASDumpRs ($dumpfile, $outfile) {
	$dumpfile = "C:\Users\Administrator\Desktop\MEMORY.DMP"
	#根据Dump文件大小计算dump分析时长
	$sleeptime_filesizetmp = Get-ChildItem $dumpfile.FullName -recurse | Measure-Object -property length -sum
	$sleeptime_filesize = $sleeptime_filesizetmp.sum
	$DUMPsleeptime = ($sleeptime_filesize/1024/1024) / 25.125
	$DUMPMemsleeptime = (($sleeptime_filesize/1024/1024) / 25.125) * 4
	$DUMPLocksleeptime = (($sleeptime_filesize/1024/1024) / 25.125) * 2
	#自动分析dmp文件
	.\windbg.exe -z "$dumpfile" -c "!analyze -v" -logo "dumpfile.log" -y ".\sysmbols"
	sleep $DUMPsleeptime
	Get-Process -Name windbg | foreach-object{ $_.Kill() }
	#自动获取异常行hash值
	$dumphashline = (Get-Content "dumpfile.log")[-7]
	#提取关键地址段
	$hashindexaddresstmp = $dumphashline.Split("!")[1]
	$hashindexaddress = "!$hashindexaddresstmp"
	.\windbg.exe -z "$dumpfile" -c "u $hashindexaddress" -logo "hashindex.log"  -y ".\sysmbols"
	sleep $sleeptime
	Get-Process -Name windbg | foreach-object{ $_.Kill() }
	#解析关键地址段1
	$hashkeyword = $hashindexaddress
	$line = 0
	Get-Content "hashindex.log" | foreach {
		$line++
		if ($_.Contains($hashkeyword))
		{
			$hashaddressanaline = $line + 1
		}
	}
	$hashaddressana = ((((Get-Content "hashindex.log")[$hashaddressanaline]).split("["))[1].split("+"))[0]
	$addnum = (((((Get-Content "hashindex.log")[$hashaddressanaline]).split("["))[1].split("+"))[1].split("]"))[0]
	#解析未加偏移量的真实地址
	.\windbg.exe -z "$dumpfile" -c "r $hashaddressana" -logo "indexaddress1.log" -y ".\sysmbols"
	sleep 5
	$indexaddress1tmp = (((Get-Content "indexaddress1.log")[-1]).split("="))[1]
	#解析加偏移量真实地址
	.\windbg.exe -z "$dumpfile" -c "? $indexaddress1tmp+$addnum" -logo "indexaddress2.log" -y ".\sysmbols"
	sleep 5
	Get-Process -Name windbg | foreach-object{ $_.Kill() }
	$indexaddress = (((Get-Content "indexaddress2.log")[-1]).split("= "))[5]
	#解析加偏移量真实地址所对应的最后一帧
	.\windbg.exe -z "$dumpfile" -c "dd $indexaddress l1" -logo "indexaddress3.log" -y ".\sysmbols"
	sleep 5
	Get-Process -Name windbg | foreach-object{ $_.Kill() }
	$indexaddress2 = (((Get-Content "indexaddress3.log")[-1]).split(" "))[2]
	#解析加偏移量真实地址所对应的最后一帧对应函数
	.\windbg.exe -z "$dumpfile" -c "dt $indexaddress2" -logo "dumpres.log" -y ".\sysmbols"
	sleep 5
	Get-Process -Name windbg | foreach-object{ $_.Kill() }
	#获取Crash时内存情况
	.\windbg.exe -z "$dumpfile" -c "!memusage" -logo "dumpmemuse.log"  -y ".\sysmbols"
	sleep $DUMPMemsleeptime
	Get-Process -Name windbg | foreach-object{ $_.Kill() }
	#获取Crash时Locks情况
	.\windbg.exe -z "$dumpfile" -c "!locks" -logo "dumpmemlocks.log"  -y ".\sysmbols"
	sleep $DUMPLocksleeptime
	Get-Process -Name windbg | foreach-object{ $_.Kill() }
	#清理分析环境
	Remove-Item indexaddress1.log -Force -Confirm:$false -recurse
	Remove-Item indexaddress2.log -Force -Confirm:$false -recurse
	Remove-Item indexaddress3.log -Force -Confirm:$false -recurse
	Remove-Item hashindex.log -Force -Confirm:$false -recurse
	#输出为dumpmemlocks.log、dumpmemuse.log、dumpres.log
	Get-Content dumpres.log | Out-File -Append ".\$outfile"
	Get-Content dumpmemuse.log | Out-File -Append ".\$outfile"
	Get-Content dumpmemlocks.log | Out-File -Append ".\$outfile"
	Remove-Item dumpres.log -Force -Confirm:$false -recurse
	Remove-Item dumpmemuse.log -Force -Confirm:$false -recurse
	Remove-Item dumpmemlocks.log -Force -Confirm:$false -recurse
}
