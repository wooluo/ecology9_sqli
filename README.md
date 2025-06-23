## ⚠️ 免责声明
本工具仅供 **学习与授权测试使用**。请勿用于非法用途，否则后果自负。开发者不对任何因使用本工具所导致的法律问题负责。

![image](https://github.com/user-attachments/assets/d6ee1611-b123-44f7-8551-8b81e4987574)

## 🔧 功能特性
+ 支持单个 URL 和批量 URL 文件输入
+ 基于响应时间判断是否存在 SQL 注入
+ 多线程并发检测，提升扫描效率
+ 自动协议补全与端口识别（如 http/https）
+ 支持保存检测结果
+ 支持详细输出模式（verbose）

##  🛠  使用方法
### 依赖环境
+ Python 3.6+
+ `requests`

 安装依赖：  

```bash
pip install requests
```

### 基本参数说明  
| 参数 | 说明 |
| --- | --- |
| `-t`                  `--target` | 指定单个目标 URL |
| `-f`                  `--file` | 从文件中批量导入目标 URL，每行一个 |
| `-o`                  `--output` | 将扫描结果输出保存到指定文件 |
| `-T`                  `--threads` | 并发线程数（默认：5） |
| `-v`                  `--verbose` | 显示详细目标输出信息 |


### 使用示例
  
检查单个目标

```bash
python ecology9_sqli.py.py -t http://example.com
```

批量检测目标（指定线程10）

```bash
python ecology9_sqli.py.py -f targets.txt -T 10
```

保存结果并显示详细信息并保存结果

```plain
python3 ecology9_sqli.py -f targets.txt -o result.txt -v
```





