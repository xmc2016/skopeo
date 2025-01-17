# skopeo list-repos

## 描述

列出指定 SOURCE-IMAGE 中的所有仓库。

## 用法

```sh
skopeo list-repos [command options] SOURCE-IMAGE
```

## 选项

- `--registry-type`: 指定 registry 类型（例如：`registry`, `harbor`）。
- `--username`: 指定用户名。
- `--password`: 指定密码。
- `--tls-verify`: 是否验证 TLS 证书，默认为 `true`。

## 示例

```sh
skopeo list-repos docker://docker.io
skopeo list-repos --registry-type=harbor docker://harbor.example.com
skopeo list-repos --registry-type=harbor --username "xxx" --password "xxx" --tls-verify=false docker://harbor.example.com
```
