## 177基板与177B-1补丁（2026-10-16）

双端完整基板及回退下限为177。175/176保留签名相邻升级链；旧于175的Web实例走保数据修复安装。177B-1修复Windows全部下载的系统“另存为”、Blob在选择保存位置期间过早释放、以及旧助手更新后重新启动旧GUI的问题；更新后核对实际GUI进程，空闲时自动完成一次启动交接。发现补丁与更新检测显示W-win-177B-1或W-linux-177B-1，顶栏保留主版本177。后台核验已有签署，确认未签署才显示条款。

GitHub只托管源码与版本记录，不上传任何安装器、镜像、热更新、补丁或源码附件。所有包统一从https://watchtowers.info/下载。补丁沿签名链升级；旧冻结控制器先获得预签名177接续桥，再交由新控制器获取补丁。账号、配置、会话和证据不随代码更新覆盖。

#176 delivery /176升级与安装

176 follows the175 installation boundary. Both products use a175↔176 adjacent pair of prebuilt common/platform ZIPs, signed inventories and ownership-aware removal; users do not download a full system for ordinary updates. The175 Web image remains the installation base. Windows new installations use the176 complete setup EXE with folder browsing; existing175 users hotupdate without reinstalling.

Copy/zoom settings reside in the Windows GUI executable. The hot update includes that rebuilt executable and uses the persistent native guardian to replace it after closing the owned process tree. Backend/frontend fixes are delivered in the same pair; the two products share compatible common members, not Linux tool binaries.

Console files are owner-authorized and saved into the existing session workspace. Progress remains below100 until the backend confirms persistence. Uploading never executes or calls the model. Single-file limit16MiB accommodates the deployed Web proxy20MiB request ceiling. Cancellation stops unfinished transport; already saved files reappear in the file list.

System notices and installed-version notices are different from changelog upgrade instructions. The server filters installed version and OS/product metadata; the frontend presents one popup at a time. Disk usage percentage is display-only: absolute writable headroom and memory budgets govern resource capacity.

Rollback175 remains the floor, and subsequent upgrades and rollbacks must stay adjacent. User data and credentials are never release members. Windows11 is the physically tested platform; Windows10 needs a separate machine. No model API calls or unverified Android prototype are part of this validation.
