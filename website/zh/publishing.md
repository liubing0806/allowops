# 签名与发布 {#signing-and-publishing}

目录使用 Ed25519 签名，签名封装在 Dead Simple Signing Envelope（DSSE）中。请分别向网关和每台主机分发公钥。网关不能在主机的信任目录中添加或吊销密钥。

## 准备签名身份 {#prepare-a-signing-identity}

在受控机器上创建一次密钥对：

```sh
allowops catalog keygen --private-key catalog-key.pem --public-key catalog.pub.pem
```

私钥为 PKCS8 PEM 格式，文件权限为 0600。公钥为 PKIX PEM 格式。把私钥移入 CI 凭据存储。不要提交私钥，也不要随目录分发私钥。把公钥作为属于 root 的文件安装到每台主机的 `/etc/allowops/catalog-keys/`，以及网关配置的密钥目录中。

## 校验、构建、签名、发布 {#validate-build-sign-publish}

以下是发布流程。在 CI 中，`ALLOWOPS_SIGNING_KEY_FILE` 是绑定到凭据存储的文件，`ALLOWOPS_PUBLISHER_TOKEN` 是绑定的密钥环境变量，`ALLOWOPS_GATEWAY_CA_FILE` 是受信任的 TLS CA 文件。

```sh
allowops catalog validate examples/catalog
allowops catalog build --dir examples/catalog --out catalog.json
allowops catalog sign --in catalog.json --out catalog.dsse.json \
  --key "$ALLOWOPS_SIGNING_KEY_FILE"
allowops catalog publish -f catalog.dsse.json \
  --gateway https://gateway.example.org \
  --ca-file "$ALLOWOPS_GATEWAY_CA_FILE" --token-env ALLOWOPS_PUBLISHER_TOKEN
```

构建会记录 Git commit、UTC `YYYYMMDDHHMMSS` 格式的版本、创建时间和过期时间。`--git-commit` 用于显式提供源 commit。`--ttl` 默认为从**构建时间**起 2160h（90 天）。签名不会延长过期时间。网关、agent 和特权辅助程序都会校验签名和过期时间。发布的版本必须递增。回滚需要发布一个新版本，其内容为经过评审的旧版本内容。动作名称在当前所有目录中必须唯一。

发布过程使用分阶段、带摘要校验的上传，以及原子发布。网关通知主机，主机拉取并校验签名后的字节内容，然后才上报加载结果。发布后，请在控制台中检查目录分发情况和不支持的动作。仅凭发布响应不能证明每台主机都已加载该目录。

## CI 边界 {#ci-boundary}

GitHub Actions、Jenkins 和 Flow 可参考[流水线示例](https://github.com/liubing0806/allowops/tree/main/examples/pipelines)。通过评审保护发布分支。通过 CI 平台的权限设置把凭据访问限制在该分支，不要只依赖仓库代码中的条件判断。fork 和 pull request 不能获得签名凭据。固定所安装的 CLI 版本，并校验其制品。使用隔离的 runner，并让每个目录的发布任务串行执行，以避免版本冲突。不要在日志中输出环境变量，也不要归档私钥文件。

发布账号只需要 `publish_catalog` 权限，不需要执行权限。发布时通过环境变量提供 token，不在命令参数中传递 token 值。如果响应在可能已经提交之后报告审计失败，请先查询目录历史，再决定是否重试。

## 轮换目录签名密钥 {#rotate-catalog-signing-keys}

1. 把新公钥分发到网关和所有主机。
2. 重复使用 `--key`，用两个密钥为新包签名。
3. 检查双签名包的发布结果和主机加载报告。
4. 所有需要的主机都信任新密钥后，删除旧公钥，并停用旧的 CI 凭据。

如果私钥泄露，请通过运维人员的主机管理渠道，从主机信任中删除对应的公钥。仅在网关侧吊销无法撤销主机的信任。
