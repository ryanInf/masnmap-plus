## 说明
个人根据使用习惯修改masnmap而来的一个小工具。调用masscan做全端口扫描，再调用nmap做服务识别，最后调用Finger做Web指纹识别。工具使用场景适合风险探测排查、众测等。


## 使用方法
1. 安装依赖
   ```bash
   pip3 install -r requirements.txt -i https://pypi.douban.com/simple/
   ```
2. 输入ip地址
新建ips.txt文件，并在文件内输入要扫描的ip地址。
![](images/2022-03-08-14-54-01.png)

3. 运行
   ```bash
   python3 masnmap.py
   ```
4. 输出结果
![](images/2022-03-08-14-53-47.png)


## 感谢
https://github.com/EASY233/Finger

https://github.com/starnightcyber/masnmap
