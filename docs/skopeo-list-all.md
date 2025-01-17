# skopeo list-all

## 描述

列出指定 SOURCE-IMAGE 中所有仓库及其标签。

## 用法

```sh
skopeo list-all [command options] SOURCE-IMAGE
```

## 选项

- `--output, -o`: 指定输出文件，默认为 `images.yaml`。
- `--registry-type`: 指定 registry 类型（例如：`registry`, `harbor`）。
- `--username`: 指定用户名。
- `--password`: 指定密码。
- `--tls-verify`: 是否验证 TLS 证书，默认为 `true`。

## 示例

```sh
skopeo list-all docker://docker.io
skopeo list-all --registry-type=harbor --username "xxx" --password "xxx" --tls-verify=false docker://harbor.example.com
```
