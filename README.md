# QCloud_Auto_ASDump
[暂不支持WS2012R2+]
自动分析dump环境，需要安装Windbg10+（CVM内可自动安装）配置好sysmbols，同时FullDump必须存在C:\windows下
这里最终的DT将会遍历出出错函数地址簇的数据类型与内容，若要了解哪个地址或者相临地址，建议补充使用 ln ，将在下个版本支持ln
