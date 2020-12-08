# Ladon Scanner For Python

[![Author](https://img.shields.io/badge/Author-k8gege-blueviolet)](https://github.com/k8gege) 
[![Ladon](https://img.shields.io/badge/Ladon-7.7-yellowgreen)](https://github.com/k8gege/Ladon) 
[![Bin](https://img.shields.io/badge/Ladon-Bin-ff69b4)](https://github.com/k8gege/Ladon/releases) 
[![GitHub issues](https://img.shields.io/github/issues/k8gege/Ladon)](https://github.com/k8gege/Ladon/issues) 
[![Github Stars](https://img.shields.io/github/stars/k8gege/Ladon)](https://github.com/k8gege/Ladon) 
[![GitHub forks](https://img.shields.io/github/forks/k8gege/Ladon)](https://github.com/k8gege/Ladon)
[![GitHub license](https://img.shields.io/github/license/k8gege/Ladon)](https://github.com/k8gege/Ladon)


### PyLadon
目前python版功能较少,无论在Windows还是Linux系统性能以及速度均也比不上Ladon.exe<br>
唯一的优点是跨平台,后续会添加相关功能，缺点也明显py打包程序很大，不太适合在目标使用<br>
所谓跨平台并不完全，有些老旧Linux系统，很多PY依赖包甚至编译底层依赖装不上，建议GO版<br>
<img src=https://k8gege.github.io/k8img/Ladon//py/PyLadon.PNG></img>


### 程序简介

Ladon一款用于大型网络渗透的多线程插件化综合扫描神器，含端口扫描、服务识别、网络资产、密码爆破、高危漏洞检测以及一键GetShell，支持批量A段/B段/C段以及跨网段扫描，支持URL、主机、域名列表扫描。7.5版本内置101个功能模块,外部模块18个,通过多种协议以及方法快速获取目标网络存活主机IP、计算机名、工作组、共享资源、网卡地址、操作系统版本、网站、子域名、中间件、开放服务、路由器、数据库等信息，漏洞检测包含MS17010、SMBGhost、Weblogic、ActiveMQ、Tomcat、Struts2系列等，密码爆破13种含数据库(Mysql、Oracle、MSSQL)、FTP、SSH、VNC、Windows(LDAP、SMB/IPC、NBT、WMI、SmbHash、WmiHash、Winrm)、BasicAuth、Tomcat、Weblogic、Rar等，远程执行命令包含(wmiexe/psexec/atexec/sshexec/jspshell),Web指纹识别模块可识别75种（Web应用、中间件、脚本类型、页面类型）等，可高度自定义插件POC支持.NET程序集、DLL(C#/Delphi/VC)、PowerShell等语言编写的插件,支持通过配置INI批量调用任意外部程序或命令，EXP生成器可一键生成漏洞POC快速扩展扫描能力。Ladon支持Cobalt Strike插件化扫描快速拓展内网进行横向移动。<br>

### 使用说明

ID | 主题 |  URL 
-|-|-
1 | Ladon文档主页 | https://github.com/k8gege/Ladon/wiki<br>
2 | 基础用法详解 | https://github.com/k8gege/Ladon/wiki/Ladon-Usage<br>
3 | Cobalt Strike | https://github.com/k8gege/Ladon/wiki/Ladon-&-Cobalt-Strike<br>
4 | Exp生成器使用 | https://github.com/k8gege/Ladon/wiki/LadonExp-Usage
5 | 高度自定义插件 | https://github.com/k8gege/Ladon/wiki/Ladon-Diy-Moudle
6 | 外部模块参考 | https://github.com/k8gege/K8CScan/wiki
7 | PowerLadon | https://github.com/k8gege/Ladon/wiki/Ladon-&-PowerShell
8 | PythonLadon | https://github.com/k8gege/PyLadon
9 | LinuxLadon | https://github.com/k8gege/LinuxLadon
10 | 漏洞演示视频 | https://github.com/k8gege/K8CScan/tree/master/Video
