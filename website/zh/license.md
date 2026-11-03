# 许可与参与 {#license-and-participation}

allowops 是以 MIT 许可发布的开源软件。[仓库中的 LICENSE](https://github.com/liubing0806/allowops/blob/main/LICENSE)
包含许可全文。版权持有人是 liubing。

MVP 阶段欢迎提交 issue 和建议，不接受外部代码贡献。报告缺陷时请提供最小复现步骤，并使用通用数据。漏洞请通过私密渠道报告。详见[参与方式](https://github.com/liubing0806/allowops/blob/main/CONTRIBUTING.md)。

## 第三方软件 {#third-party-software}

可选的 `allowops-arthas` 软件包再分发 Arthas（Apache License 2.0），以及 `arthas-core.jar` 中捆绑的第三方组件。软件包中出现的许可证有 Apache-2.0、BSD-3-Clause、EPL-1.0、MIT 和 0BSD，软件包元数据中有说明。`arthas-core.jar` 内的 logback 库以 Eclipse Public License 1.0 分发，软件包附有许可证文本和源码位置。软件包包含 `LICENSE`、`NOTICE` 和 `THIRD_PARTY_NOTICES`。仓库在 [deploy/packaging/arthas](https://github.com/liubing0806/allowops/tree/main/deploy/packaging/arthas) 中保存同样的文件。Go 依赖的声明在发布归档和 `allowops-agent` 的 `THIRD_PARTY_NOTICES` 中。
