# CVE PoC 搜索引擎

一个现代化的、独立的HTML版CVE PoC（概念验证）漏洞搜索引擎。**收录几乎所有公开可用的CVE PoC。**

## 功能特点

- **现代化UI设计**：支持深色/浅色主题切换，渐变背景
- **独立HTML文件**：无需服务器，浏览器直接打开即可使用
- **快速搜索**：通过CVE ID即时搜索（按回车或点击搜索按钮）
- **多数据源**：合并多个JSON数据源
- **响应式设计**：支持桌面和移动设备
- **主题记忆**：记住用户的主题偏好

## 使用方法

### 生成搜索页面

运行生成脚本创建HTML搜索页面：

```bash
python3 generate_search.py
```

脚本会：
1. 从 `config.json` 定义的所有数据源加载CVE数据
2. 生成 `index.html`（数据已嵌入）
3. 显示统计信息（CVE条目数和PoC链接数）

### 打开搜索页面

直接在浏览器中打开 `index.html`：
- 双击文件
- 或使用命令：`firefox index.html`

### 搜索CVE

1. 输入CVE编号（如 `CVE-2024-1234` 或直接输入 `2024`）
2. 按回车键或点击搜索按钮
3. 结果会显示CVE编号及对应的PoC链接

## 配置说明

编辑 `config.json` 添加/删除数据源：

```json
{
  "sources": [
    "unsafe/cve_poc_unsafe.json",
    "trickest/trickest_cve.json"
  ]
}
```

## 数据格式

JSON文件应遵循以下格式：

```json
[
  {"CVE": "CVE-2021-44228", "PoC": "https://github.com/example/log4j-poc"},
  {"CVE": "CVE-2021-44228", "PoC": "https://github.com/another/log4j-demo"},
  ...
]
```

## 数据统计

当前数据包含：
- **118,304** 个CVE条目
- **175,786** 个PoC链接

## 数据来源

- [trickest/cve](https://github.com/trickest/cve) - 全面的CVE参考链接集合
- 自定义PoC收集

## 许可证

本项目仅供教育和安全研究目的使用。

## 免责声明

请负责任地使用这些PoC资源。仅在你拥有或获得明确授权的系统上进行测试。未经授权使用漏洞利用可能违法。