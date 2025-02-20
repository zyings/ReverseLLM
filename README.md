# ReverseLLM

ReverseLLM 是一个IDA Pro插件，它利用大语言模型(LLM)来辅助二进制程序的逆向分析工作。本插件基于开源项目WPeChatGPT进行定制化修改，主要特点是支持多个模型灵活切换，优化了使用体验。

## ✨ 主要功能

- 🔍 **智能函数分析** (快捷键: Ctrl+Alt+G)
  - 深入分析函数目的和功能逻辑
  - 详细解释参数作用和数据流向
  - 智能推荐更准确的函数命名

- 🏷️ **变量智能重命名** (快捷键: Ctrl+Alt+R) 
  - 基于上下文分析变量用途
  - 自动推荐语义化的变量名称
  - 支持批量重命名操作
  - 保持代码命名风格统一

- 🐍 **Python代码还原**
  - 将反编译的C代码转换为等效Python实现
  - 提供更直观的代码逻辑展示
  - 辅助理解程序执行流程

- 🔒 **安全漏洞扫描** (快捷键: Ctrl+Alt+E)
  - 自动检测常见漏洞模式
  - 分析潜在的安全风险
  - 提供详细的漏洞描述
  - 给出修复建议和防护方案

- 💉 **漏洞利用验证**
  - 自动生成漏洞验证PoC代码
  - 提供Python格式的测试脚本
  - 辅助验证漏洞可利用性

## 🚀 快速开始

### 安装要求

- Python 3.x
- IDA Pro 7.0+
- 网络连接(用于API调用)

### 安装步骤

1. 安装依赖包:

```bash
pip install -r requirements.txt
```

2. 配置模型信息:

- 修改`ModelConfig.json`文件，填入你的API密钥和相关配置，需要配置default_model指定一个默认的模型

```json
{
    "name": "gpt-3.5-turbo",
    "display_name": "GPT-3.5",
    "api_key": "YOUR_API_KEY",
    "base_url": "https://api.openai.com/v1",
    "proxy": "http://127.0.0.1:7890"  // 可选代理设置
}
```

3. 部署插件:

- 将`ReverseLLM.py`和`ModelConfig.json`复制到IDA插件目录
- 重启IDA使插件生效

## 💡 使用技巧

- 使用快捷键可以快速触发常用功能
- 可以通过配置文件灵活切换不同的模型
- 支持配置代理来解决网络访问问题
- 分析结果会自动保存在IDA数据库中

## 📝 注意事项

1. 分析结果仅供参考，建议结合人工判断
2. 请确保API密钥配置正确且有足够的调用额度
3. 所有功能仅供研究学习使用，请勿用于非法用途

## 🤝 贡献与反馈

- 欢迎提交Issue反馈使用问题
- 欢迎提交Pull Request改进代码
- 如有其他问题可通过邮件联系

## 📜 致谢

本项目受到[WPeChatGPT](https://github.com/WPeace-HcH/WPeChatGPT)项目的启发，特此感谢。

## 📄 许可证

本项目采用MIT许可证，详见[LICENSE](LICENSE)文件。
