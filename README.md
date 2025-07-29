# OSS对象存储实现

这是一个基于Python Flask的对象存储服务(OSS)实现，支持S3协议兼容，使用本地文件系统进行存储。

## 功能特性

### 核心功能
- ✅ 存储桶管理（创建、删除、列表）
- ✅ 存储桶权限控制（私有、公共读、公共读写）
- ✅ 对象管理（上传、下载、删除、列表）
- ✅ 本地文件系统存储
- ✅ S3协议兼容性
- ✅ RESTful API接口
- ✅ 现代化Web管理界面
- ✅ 预签名URL生成

### S3兼容性
- ✅ 支持S3风格的API端点
- ✅ XML响应格式
- ✅ 标准HTTP状态码
- ✅ 支持查询参数（prefix、marker、max-keys、delimiter）
- ✅ 支持PUT/POST两种上传方式
- ✅ 预签名URL生成和验证
- ✅ AWS Signature Version 4签名验证
- ✅ Content-MD5验证
- ✅ 条件请求支持（If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since）
- ✅ Range请求支持
- ✅ HEAD对象请求
- ✅ 批量删除对象
- ✅ 对象复制功能
- ✅ 分页和分隔符支持

### Web界面
- ✅ 响应式设计，支持移动端
- ✅ 实时状态监控
- ✅ 拖拽上传文件
- ✅ 文件预览和下载
- ✅ 磁盘使用量显示（header位置）
- ✅ 存储桶权限显示
- ✅ 对象链接复制功能
- ✅ 预签名URL生成
- ✅ 管理界面认证
- ✅ 文件夹管理
- ✅ 无文件大小限制上传


![](https://image.101723.xyz/202507/29134043118.png)
![](https://image.101723.xyz/202507/29134114577.png)
![](https://image.101723.xyz/202507/29134134518.png)
![](https://image.101723.xyz/202507/29134209295.png)
![](https://image.101723.xyz/202507/29134228460.png)
![](https://image.101723.xyz/202507/29134255560.png)
![](https://image.101723.xyz/202507/29134326148.png)

## 快速开始

### docker 快速启动

```bash

docker build -t pyio .

docker run --rm -it -p 15000:15000 -v $(pwd)/data:/data -e STORAGE_PATH=/data -e ACCESS_KEY=admin -e SECRET_KEY=secret123 --name pyio pyio:latest
```

## 使用方法

### 1. 安装依赖

```bash
# 激活虚拟环境
source .venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 2. 启动服务器（推荐方式）

```bash
# 使用默认配置启动
python start_oss.py

# 指定存储路径启动
python start_oss.py --storage-path /data/oss

# 完整配置启动
python start_oss.py --storage-path /mnt/data --port 9000 --access-key admin --secret-key secret123

# 检查存储路径权限
python start_oss.py --check-path --storage-path /data/oss
```

这个脚本提供：
- 友好的命令行参数解析
- 存储路径权限检查
- 详细的启动信息显示
- 灵活的配置选项

### 3. 启动服务器（直接方式）

```bash
# 无认证启动
python oss_server.py

# 带认证启动
python oss_server.py --access-key admin --secret-key password

# 自定义端口和存储路径启动
python oss_server.py --port 8080 --storage-path /data/oss --access-key admin --secret-key password

# 调试模式启动
python oss_server.py --debug --storage-path /tmp/oss_test
```

### 4. 访问Web界面

启动服务器后，在浏览器中访问：
- **自动启动**: 浏览器会自动打开 `http://localhost:15000`
- **手动访问**: 打开浏览器访问 `http://localhost:15000`

**注意**: 如果启用了管理认证，浏览器会弹出认证对话框，请输入设置的访问密钥和密钥

### 5. 使用Python客户端

```python
from oss_client import OSSClient

# 创建客户端
client = OSSClient('http://localhost:15000')

# 创建存储桶
client.create_bucket('my-bucket')

# 上传文件
client.upload_object('my-bucket', 'test.txt')

# 列出对象
objects = client.list_objects('my-bucket')
```

### 6. 使用S3兼容客户端

```python
from s3_client import SimpleS3Client

# 创建S3客户端
s3_client = SimpleS3Client('http://localhost:15000')

# 创建存储桶
s3_client.create_bucket('my-bucket')

# 上传对象
s3_client.put_object('my-bucket', 'test.txt', b'Hello World')

# 列出对象
objects = s3_client.list_objects('my-bucket')
```

### 7. 使用AWS SDK (boto3)

```python
import boto3

# 创建S3客户端
s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:15000',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1'
)

# 创建存储桶
s3_client.create_bucket(Bucket='my-bucket')

# 上传对象
s3_client.put_object(
    Bucket='my-bucket',
    Key='test.txt',
    Body=b'Hello World',
    ContentType='text/plain'
)

# 列出对象
response = s3_client.list_objects_v2(Bucket='my-bucket')
for obj in response.get('Contents', []):
    print(obj['Key'])
```

## S3兼容性测试

### 运行兼容性测试

```bash
# 确保服务器正在运行
python oss_server.py

# 在另一个终端运行测试
python test_s3_compatibility.py
```

### 测试内容

测试脚本会验证以下S3功能：

1. **基本操作**
   - 创建/删除存储桶
   - 上传/下载/删除对象
   - 列出存储桶和对象
   - HEAD对象请求

2. **高级功能**
   - 对象复制
   - 批量删除
   - 条件请求
   - 分页和分隔符
   - 前缀过滤

3. **认证和签名**
   - AWS Signature Version 4
   - Content-MD5验证
   - 权限控制

## API参考

### 存储桶操作

#### 创建存储桶
```http
PUT /{bucket-name}
```

#### 删除存储桶
```http
DELETE /{bucket-name}
```

#### 列出存储桶
```http
GET /
```

### 对象操作

#### 上传对象
```http
PUT /{bucket-name}/{object-name}
POST /buckets/{bucket-name}/objects
```

#### 下载对象
```http
GET /{bucket-name}/{object-name}
GET /buckets/{bucket-name}/objects/{object-name}
```

#### 删除对象
```http
DELETE /{bucket-name}/{object-name}
DELETE /buckets/{bucket-name}/objects/{object-name}
```

#### 列出对象
```http
GET /{bucket-name}?prefix=&delimiter=&max-keys=&marker=
GET /buckets/{bucket-name}/objects?prefix=&delimiter=&max-keys=&marker=
```

#### HEAD对象
```http
HEAD /{bucket-name}/{object-name}
```

#### 复制对象
```http
PUT /{bucket-name}/{object-name}
X-Amz-Copy-Source: /source-bucket/source-object
```

#### 批量删除对象
```http
POST /{bucket-name}?delete
```

### 查询参数

- `prefix`: 对象名称前缀过滤
- `delimiter`: 分隔符（通常为"/"）
- `max-keys`: 最大返回对象数量（1-1000）
- `marker`: 分页标记

### 请求头

#### 认证
- `Authorization`: AWS签名
- `X-Amz-Date`: 请求时间戳
- `X-Amz-Content-Sha256`: 请求体哈希

#### 条件请求
- `If-Match`: ETag匹配条件
- `If-None-Match`: ETag不匹配条件
- `If-Modified-Since`: 修改时间条件
- `If-Unmodified-Since`: 未修改时间条件

#### 内容验证
- `Content-MD5`: 内容MD5哈希
- `Content-Type`: 内容类型

#### 范围请求
- `Range`: 字节范围请求

## 配置选项

### 命令行参数

- `--access-key`: 管理访问密钥
- `--secret-key`: 管理密钥
- `--port`: 服务器端口（默认: 15000）
- `--host`: 服务器地址（默认: 0.0.0.0）
- `--debug`: 启用调试模式

### 环境变量

- `OSS_ACCESS_KEY`: 访问密钥
- `OSS_SECRET_KEY`: 密钥
- `OSS_PORT`: 端口
- `OSS_HOST`: 主机地址

## 故障排除

### 常见问题

1. **S3客户端连接失败**
   - 检查服务器是否正在运行
   - 验证端口和地址配置
   - 确认访问密钥和密钥正确

2. **签名验证失败**
   - 检查系统时间是否正确
   - 验证请求头格式
   - 确认签名算法版本

3. **权限拒绝**
   - 检查存储桶权限设置
   - 验证认证信息
   - 确认操作权限

### 调试模式

启动调试模式以获取详细日志：

```bash
python oss_server.py --debug
```

## 开发指南

### 项目结构

```
oss-implementation/
├── oss_server.py          # 主服务器文件
├── oss_client.py          # Python客户端
├── s3_client.py           # S3兼容客户端
├── test_s3_compatibility.py # S3兼容性测试
├── start_oss.py           # 启动脚本
├── start_server.py        # 服务器启动脚本
├── oss_ui.html           # Web界面
├── requirements.txt       # 依赖列表
├── buckets.json          # 存储桶配置
└── README.md             # 项目文档
```

### 扩展功能

1. **添加新的S3 API**
   - 在`oss_server.py`中添加新的路由
   - 实现相应的处理函数
   - 添加XML响应生成

2. **自定义存储后端**
   - 修改存储相关函数
   - 实现新的存储接口
   - 更新配置管理

3. **增强认证机制**
   - 实现更复杂的权限控制
   - 添加角色和策略支持
   - 集成外部认证服务

## 许可证

MIT
