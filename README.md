# HookSigntool
## 简介
本项目修改自JemmyLoveJenny发布的修改版数字签名工具（算是二改罢）\
原始版本的README请查看本目录下的[README_Original.md](README_Original.md)

## 我修改了什么？
修改伪造时间戳部分，因为JemmyLoveJenny开放的时间戳服务器关闭了，无法进行签名，所以将伪造时间戳修改为自定义时间戳服务器的URL\
可以配合同作者开发的TimeStampResponder（本人也有修改版本，支持SHA1与SHA256双时间戳）搭建本地时间戳服务器，实现无限制的伪造时间戳\
修改了命令行传入的部分，删除 -ts 参数，添加 --timestamp-sha1 参数传递SHA1时间戳URL，--timestamp-sha256 参数传递SHA256时间戳URL\
其余功能均与原作者的HookSigntool一致\
有关使用和更多详细说明，请查看[README_Original.md](README_Original.md)\
此工具仅供娱乐，伪造时间戳是虚假的时间戳，无法被系统承认，故因此无法用于恶意用途，如有修改为恶意用途者，请立即向当地公安部门举报