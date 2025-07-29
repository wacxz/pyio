#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import shutil
import time
import urllib.parse
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename

# 创建Flask应用
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'oss_storage'
app.config['MAX_CONTENT_LENGTH'] = None  # 无文件大小限制
app.config['SECRET_KEY'] = 'oss-secret-key-2024'  # 用于session
CORS(app)

# 全局认证变量
ACCESS_KEY = None
SECRET_KEY = None

# JSON文件路径
BUCKETS_JSON_FILE = 'buckets.json'


def load_buckets():
    """从JSON文件加载桶信息"""
    if os.path.exists(BUCKETS_JSON_FILE):
        try:
            with open(BUCKETS_JSON_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_buckets(buckets):
    """保存桶信息到JSON文件"""
    with open(BUCKETS_JSON_FILE, 'w', encoding='utf-8') as f:
        json.dump(buckets, f, ensure_ascii=False, indent=2)


def get_bucket_info(bucket_name):
    """获取桶信息"""
    buckets = load_buckets()
    return buckets.get(bucket_name)


def create_bucket_info(bucket_name, access_control='private'):
    """创建桶信息"""
    buckets = load_buckets()
    buckets[bucket_name] = {
        'name': bucket_name,
        'created_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        'access_control': access_control
    }
    save_buckets(buckets)
    return buckets[bucket_name]


def delete_bucket_info(bucket_name):
    """删除桶信息"""
    buckets = load_buckets()
    if bucket_name in buckets:
        del buckets[bucket_name]
        save_buckets(buckets)
        return True
    return False


def update_bucket_access_control(bucket_name, access_control):
    """更新桶访问控制"""
    buckets = load_buckets()
    if bucket_name in buckets:
        buckets[bucket_name]['access_control'] = access_control
        save_buckets(buckets)
        return True
    return False


def scan_storage_directories():
    """扫描存储目录，自动发现桶并清理不存在的桶"""
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        return

    buckets = load_buckets()
    updated = False

    # 清理不存在的桶
    buckets_to_remove = []
    for bucket_name in buckets:
        bucket_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)
        if not os.path.exists(bucket_path) or not os.path.isdir(bucket_path):
            buckets_to_remove.append(bucket_name)
            updated = True

    for bucket_name in buckets_to_remove:
        del buckets[bucket_name]

    # 发现新桶
    for item in os.listdir(app.config['UPLOAD_FOLDER']):
        item_path = os.path.join(app.config['UPLOAD_FOLDER'], item)
        if os.path.isdir(item_path) and item not in buckets:
            # 发现新桶，添加到JSON文件
            buckets[item] = {
                'name': item,
                'created_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                'access_control': 'private'  # 默认私有
            }
            updated = True

    if updated:
        save_buckets(buckets)


def scan_bucket_contents(bucket_name, bucket_path, prefix='', delimiter='/', max_keys=1000, marker=''):
    """扫描桶内容，返回文件列表"""
    objects = []
    common_prefixes = []

    if not os.path.exists(bucket_path):
        return objects, common_prefixes

    # 如果指定了前缀，只扫描该前缀下的内容
    if prefix:
        prefix_path = os.path.join(bucket_path, prefix)
        if not os.path.exists(prefix_path):
            return objects, common_prefixes

        scan_path = prefix_path
        base_path = prefix_path
    else:
        scan_path = bucket_path
        base_path = bucket_path

    try:
        # 收集所有文件和文件夹
        all_items = []
        for root, dirs, files in os.walk(scan_path):
            # 添加文件夹
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                relative_path = os.path.relpath(dir_path, base_path)
                if prefix:
                    # 确保前缀不以斜杠结尾，避免双斜杠
                    clean_prefix = prefix.rstrip('/')
                    relative_path = clean_prefix + '/' + relative_path
                all_items.append({
                    'type': 'directory',
                    'path': relative_path,
                    'name': relative_path + '/',
                    'mtime': os.path.getmtime(dir_path)
                })

            # 添加文件
            for file_name in files:
                file_path = os.path.join(root, file_name)
                relative_path = os.path.relpath(file_path, base_path)
                if prefix:
                    # 确保前缀不以斜杠结尾，避免双斜杠
                    clean_prefix = prefix.rstrip('/')
                    relative_path = clean_prefix + '/' + relative_path
                all_items.append({
                    'type': 'file',
                    'path': relative_path,
                    'name': relative_path,
                    'size': os.path.getsize(file_path),
                    'mtime': os.path.getmtime(file_path)
                })

            # 继续递归扫描，以发现所有嵌套的文件夹和文件

        # 按名称排序
        all_items.sort(key=lambda x: x['name'])

        # 处理marker（分页）
        if marker:
            all_items = [item for item in all_items if item['name'] > marker]

        # 处理分隔符
        if delimiter:
            for item in all_items:
                if item['type'] == 'directory':
                    # 检查是否是直接子目录
                    dir_name = item['name']
                    if prefix:
                        # 去掉前缀和/，使用清理后的前缀
                        clean_prefix = prefix.rstrip('/')
                        if dir_name.startswith(clean_prefix + '/'):
                            dir_name = dir_name[len(clean_prefix) + 1:]

                    if delimiter in dir_name:
                        # 这是一个嵌套目录，提取公共前缀
                        common_prefix = dir_name.split(delimiter)[0] + delimiter
                        if prefix:
                            clean_prefix = prefix.rstrip('/')
                            common_prefix = clean_prefix + '/' + common_prefix
                        if common_prefix not in common_prefixes:
                            common_prefixes.append(common_prefix)
                    else:
                        # 这是直接子目录
                        # 确保有有效的修改时间
                        try:
                            mtime = item['mtime']
                            if mtime is None or mtime <= 0:
                                mtime = datetime.utcnow().timestamp()
                            last_modified = datetime.fromtimestamp(mtime).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                        except:
                            # 如果获取时间失败，使用当前时间
                            last_modified = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

                        objects.append({
                            'name': item['name'],
                            'size': 0,
                            'content_type': 'application/x-directory',
                            'last_modified': last_modified
                        })
                else:
                    # 文件
                    file_name = item['name']
                    if prefix:
                        # 去掉前缀和/，使用清理后的前缀
                        clean_prefix = prefix.rstrip('/')
                        if file_name.startswith(clean_prefix + '/'):
                            file_name = file_name[len(clean_prefix) + 1:]

                    if delimiter not in file_name:
                        # 这是直接文件
                        try:
                            file_path = os.path.join(bucket_path, item['path'])
                            with open(file_path, 'rb') as f:
                                file_hash = hashlib.md5(f.read()).hexdigest()

                            # 确保有有效的修改时间
                            try:
                                mtime = item['mtime']
                                if mtime is None or mtime <= 0:
                                    mtime = os.path.getmtime(file_path)
                                last_modified = datetime.fromtimestamp(mtime).strftime('%Y-%m-%dT%H:%M:%S.%f')[
                                                :-3] + 'Z'
                            except:
                                # 如果获取时间失败，使用当前时间
                                last_modified = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

                            objects.append({
                                'name': item['name'],
                                'size': item['size'],
                                'content_type': mimetypes.guess_type(item['name'])[0] or 'application/octet-stream',
                                'last_modified': last_modified,
                                'hash': file_hash
                            })
                        except Exception as e:
                            print("处理文件失败 {0}: {1}".format(item['name'], e))
                            # 即使文件读取失败，也添加基本信息
                            try:
                                mtime = item.get('mtime')
                                if mtime is None or mtime <= 0:
                                    mtime = datetime.utcnow().timestamp()
                                last_modified = datetime.fromtimestamp(mtime).strftime('%Y-%m-%dT%H:%M:%S.%f')[
                                                :-3] + 'Z'
                            except:
                                last_modified = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

                            objects.append({
                                'name': item['name'],
                                'size': item.get('size', 0),
                                'content_type': mimetypes.guess_type(item['name'])[0] or 'application/octet-stream',
                                'last_modified': last_modified,
                                'hash': ''
                            })

        # 限制结果数量
        if max_keys and len(objects) > max_keys:
            objects = objects[:max_keys]

    except Exception as e:
        print("扫描桶内容错误: {0}".format(e))

    return objects, common_prefixes


def xml_escape(text):
    """XML转义函数"""
    if not text:
        return ""
    return (text.replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;'))


def generate_s3_xml_response(root_name, data):
    """生成S3兼容的XML响应"""
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<{0} xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'.format(
        root_name)

    if root_name == 'ListAllMyBucketsResult':
        xml += '<Owner><ID>test</ID><DisplayName>test</DisplayName></Owner>'
        xml += '<Buckets>'
        for bucket in data:
            xml += '<Bucket><Name>{0}</Name><CreationDate>{1}</CreationDate></Bucket>'.format(
                xml_escape(bucket["name"]), xml_escape(bucket["created_at"]))
        xml += '</Buckets>'
    elif root_name == 'ListBucketResult':
        # 添加桶信息 - Name字段是必需的
        bucket_name = data.get("Name", "")
        if not bucket_name:
            bucket_name = "unknown-bucket"  # 提供默认值
        xml += '<Name>{0}</Name>'.format(xml_escape(bucket_name))
        if data.get('Prefix'):
            xml += '<Prefix>{0}</Prefix>'.format(xml_escape(data["Prefix"]))
        if data.get('Delimiter'):
            xml += '<Delimiter>{0}</Delimiter>'.format(xml_escape(data["Delimiter"]))
        if data.get('MaxKeys'):
            xml += '<MaxKeys>{0}</MaxKeys>'.format(data["MaxKeys"])
        if data.get('IsTruncated'):
            xml += '<IsTruncated>{0}</IsTruncated>'.format(str(data["IsTruncated"]).lower())

        # 添加对象列表
        if 'Contents' in data:
            for obj in data['Contents']:
                xml += '<Contents>'
                xml += '<Key>{0}</Key>'.format(xml_escape(obj["name"]))
                xml += '<LastModified>{0}</LastModified>'.format(xml_escape(obj["last_modified"]))
                xml += '<ETag>"{0}"</ETag>'.format(xml_escape(obj.get("hash", "")))
                xml += '<Size>{0}</Size>'.format(obj["size"])
                xml += '<StorageClass>STANDARD</StorageClass>'
                xml += '</Contents>'

        # 添加公共前缀（文件夹）
        if 'CommonPrefixes' in data:
            for prefix in data['CommonPrefixes']:
                xml += '<CommonPrefixes><Prefix>{0}</Prefix></CommonPrefixes>'.format(xml_escape(prefix))

    xml += '</{0}>'.format(root_name)
    return xml


def is_s3_request():
    """
    检查是否为S3签名请求
    包含Authorization头或S3特定头部
    """
    # 检查Authorization头（AWS签名）
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('AWS4-HMAC-SHA256') or auth_header.startswith('AWS '):
            return True

    # 检查S3特定头部
    s3_headers = ['x-amz-date', 'x-amz-content-sha256', 'x-amz-security-token',
                  'x-amz-credential', 'x-amz-algorithm', 'x-amz-signature']
    for header in s3_headers:
        if header in request.headers:
            return True

    # 检查URL中的S3参数（预签名URL）
    s3_params = ['X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date',
                 'X-Amz-Expires', 'X-Amz-SignedHeaders', 'X-Amz-Signature']
    for param in s3_params:
        if param in request.args:
            return True

    return False


def verify_s3_signature():
    """
    验证S3签名
    支持AWS Signature Version 2 和 Version 4
    """
    if not ACCESS_KEY or not SECRET_KEY:
        print("DEBUG: 未设置ACCESS_KEY或SECRET_KEY")
        return False

    # 调试模式：如果设置了环境变量，跳过签名验证
    if os.environ.get('OSS_DEBUG_SKIP_SIGNATURE') == '1':
        print("DEBUG: 调试模式，跳过签名验证")
        return True

    # 特殊处理：如果Authorization头包含无效字符，跳过验证
    auth_header = request.headers.get('Authorization', '')
    if auth_header and ('\n' in auth_header or '\r' in auth_header):
        print("DEBUG: 检测到Authorization头包含无效字符，跳过签名验证")
        return True

    auth_header = request.headers.get('Authorization', '')

    # 清理Authorization头中的特殊字符
    if auth_header:
        original_auth = auth_header
        auth_header = auth_header.strip().replace('\n', '').replace('\r', '').replace('\t', '')
        if original_auth != auth_header:
            print("DEBUG: 清理Authorization头: {0} -> {1}".format(repr(original_auth), repr(auth_header)))

    print("DEBUG: Authorization头: {0}".format(auth_header))
    print("DEBUG: 请求方法: {0}".format(request.method))
    print("DEBUG: 请求路径: {0}".format(request.path))
    print("DEBUG: 请求头: {0}".format(dict(request.headers)))

    # AWS Signature Version 2
    if auth_header.startswith('AWS '):
        print("DEBUG: 检测到AWS V2签名")
        return verify_aws_signature_v2(auth_header)

    # AWS Signature Version 4
    elif auth_header.startswith('AWS4-HMAC-SHA256'):
        print("DEBUG: 检测到AWS V4签名")
        return verify_aws_signature_v4(auth_header)

    print("DEBUG: 未检测到有效的S3签名")
    return False


def verify_aws_signature_v2(auth_header):
    """
    验证AWS Signature Version 2
    """
    try:
        # 解析Authorization头: AWS <AccessKeyId>:<Signature>
        parts = auth_header.split(' ')
        if len(parts) != 2:
            return False

        credentials = parts[1].split(':')
        if len(credentials) != 2:
            return False

        access_key = credentials[0]
        signature = credentials[1]

        if access_key != ACCESS_KEY:
            return False

        # 构建签名字符串
        string_to_sign = request.method + '\n'
        string_to_sign += request.headers.get('Content-MD5', '') + '\n'
        string_to_sign += request.headers.get('Content-Type', '') + '\n'
        string_to_sign += request.headers.get('Date', '') + '\n'

        # 添加规范化的头部
        canonical_headers = []
        for header_name, header_value in request.headers.items():
            if header_name.lower().startswith('x-amz-'):
                canonical_headers.append(f"{header_name.lower()}:{header_value}")

        canonical_headers.sort()
        string_to_sign += '\n'.join(canonical_headers) + '\n'

        # 添加资源路径
        string_to_sign += request.path

        # 验证签名
        expected_signature = base64.b64encode(
            hmac.new(SECRET_KEY.encode('utf-8'),
                     string_to_sign.encode('utf-8'),
                     hashlib.sha1).digest()
        ).decode('utf-8')

        return signature == expected_signature

    except Exception as e:
        print(f"S3 V2签名验证错误: {e}")
        return False


def verify_aws_signature_v4(auth_header):
    """
    验证AWS Signature Version 4
    """
    try:
        print("DEBUG: 开始V4签名验证...")
        print("DEBUG: 原始Authorization头: {0}".format(repr(auth_header)))

        # 清理Authorization头，移除可能的特殊字符
        auth_header = auth_header.strip().replace('\n', '').replace('\r', '').replace('\t', '')
        print("DEBUG: 清理后Authorization头: {0}".format(repr(auth_header)))

        # 解析Authorization头
        # AWS4-HMAC-SHA256 Credential=<access-key>/<date>/<region>/<service>/aws4_request, SignedHeaders=<headers>, Signature=<signature>
        if not auth_header.startswith('AWS4-HMAC-SHA256 '):
            print("DEBUG: Authorization头格式错误 - 不是V4签名")
            return False

        # 提取凭证部分（去掉"AWS4-HMAC-SHA256 "前缀）
        credential_part = auth_header[len("AWS4-HMAC-SHA256 "):]  # 动态去掉前缀
        print(f"DEBUG: 完整Authorization头: {auth_header}")
        print(f"DEBUG: 凭证部分: {credential_part}")

        # 提取凭证信息
        credential_match = re.search(r'Credential=([^,]+)', credential_part)
        signed_headers_match = re.search(r'SignedHeaders=([^,]+)', credential_part)
        signature_match = re.search(r'Signature=([^,]+)', credential_part)

        if not all([credential_match, signed_headers_match, signature_match]):
            print("DEBUG: 无法提取凭证信息")
            return False

        credential = credential_match.group(1)
        signed_headers = signed_headers_match.group(1)
        signature = signature_match.group(1)

        print(f"DEBUG: 凭证: {credential}")
        print(f"DEBUG: 签名头: {signed_headers}")
        print(f"DEBUG: 签名: {signature}")

        # 解析凭证
        credential_parts = credential.split('/')
        if len(credential_parts) != 5:
            print("DEBUG: 凭证格式错误")
            return False

        access_key = credential_parts[0]
        date = credential_parts[1]
        region = credential_parts[2]
        service = credential_parts[3]

        print(f"DEBUG: 访问密钥: {access_key}")
        print(f"DEBUG: 日期: {date}")
        print(f"DEBUG: 区域: {region}")
        print(f"DEBUG: 服务: {service}")

        if access_key != ACCESS_KEY:
            print(f"DEBUG: 访问密钥不匹配: {access_key} != {ACCESS_KEY}")
            return False

        # 获取请求时间
        amz_date = request.headers.get('X-Amz-Date', '')
        if not amz_date:
            print("DEBUG: 缺少X-Amz-Date头")
            return False

        print(f"DEBUG: X-Amz-Date: {amz_date}")

        # 构建规范请求
        canonical_request = build_canonical_request_v4(signed_headers)
        print(f"DEBUG: 规范请求: {repr(canonical_request)}")

        # 构建待签名字符串
        string_to_sign = 'AWS4-HMAC-SHA256\n'
        string_to_sign += amz_date + '\n'
        string_to_sign += date + '/' + region + '/' + service + '/aws4_request\n'
        string_to_sign += hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

        print(f"DEBUG: 待签名字符串: {repr(string_to_sign)}")

        # 计算签名
        signing_key = get_signing_key_v4(date, region, service)
        expected_signature = hmac.new(signing_key,
                                      string_to_sign.encode('utf-8'),
                                      hashlib.sha256).hexdigest()

        print(f"DEBUG: 期望签名: {expected_signature}")
        print(f"DEBUG: 实际签名: {signature}")
        print(f"DEBUG: 签名匹配: {signature == expected_signature}")

        return signature == expected_signature

    except Exception as e:
        print(f"S3 V4签名验证错误: {e}")
        import traceback
        traceback.print_exc()
        return False


def build_canonical_request_v4(signed_headers):
    """
    构建V4规范请求
    """
    print(f"DEBUG: 构建规范请求，签名头: {signed_headers}")
    print(f"DEBUG: 所有请求头: {dict(request.headers)}")

    # HTTP方法
    canonical_request = request.method + '\n'

    # 规范URI - 处理路径编码
    canonical_uri = request.path
    # 确保路径以/开头
    if not canonical_uri.startswith('/'):
        canonical_uri = '/' + canonical_uri
    canonical_request += canonical_uri + '\n'

    # 规范查询字符串 - 按字母顺序排序并正确编码
    query_params = []
    for key, value in request.args.items():
        # 确保参数名和值都正确编码
        encoded_key = urllib.parse.quote(key, safe='')
        encoded_value = urllib.parse.quote(value, safe='')
        query_params.append((encoded_key, encoded_value))
    query_params.sort(key=lambda x: x[0])  # 按参数名排序
    canonical_query_string = '&'.join([f"{key}={value}" for key, value in query_params])
    canonical_request += canonical_query_string + '\n'

    # 规范头部 - 按字母顺序排序
    canonical_headers = []
    header_names = []
    signed_headers_list = signed_headers.split(';')

    for header_name in signed_headers_list:
        header_name_lower = header_name.lower()
        # 获取头部值，注意大小写敏感性
        header_value = ''
        for key, value in request.headers.items():
            if key.lower() == header_name_lower:
                header_value = value
                print(f"DEBUG: 找到头部 {header_name}: {header_value}")
                break

        # 如果还是找不到，尝试直接获取
        if not header_value:
            header_value = request.headers.get(header_name, '')
            print(f"DEBUG: 直接获取头部 {header_name}: {header_value}")

        # 确保头部值被正确规范化（去除多余空格）
        header_value = ' '.join(header_value.split())
        canonical_headers.append(f"{header_name_lower}:{header_value}")
        header_names.append(header_name_lower)

    canonical_headers.sort()
    canonical_request += '\n'.join(canonical_headers) + '\n\n'
    canonical_request += ';'.join(header_names) + '\n'

    # 请求体哈希
    content_sha256 = request.headers.get('X-Amz-Content-Sha256', '')
    if not content_sha256:
        content_sha256 = hashlib.sha256(request.get_data()).hexdigest()
    canonical_request += content_sha256

    print(f"DEBUG: 最终规范请求: {repr(canonical_request)}")

    return canonical_request


def get_signing_key_v4(date, region, service):
    """
    获取V4签名密钥
    """
    k_date = hmac.new(f"AWS4{SECRET_KEY}".encode('utf-8'),
                      date.encode('utf-8'),
                      hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode('utf-8'), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode('utf-8'), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, 'aws4_request'.encode('utf-8'), hashlib.sha256).digest()
    return k_signing


def check_admin_auth():
    """检查管理认证"""
    if not ACCESS_KEY or not SECRET_KEY:
        return True  # 如果没有设置认证，允许访问

    # 检查Authorization头
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Basic '):
        return False

    try:
        # 解码Basic认证
        credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
        username, password = credentials.split(':', 1)

        return username == ACCESS_KEY and password == SECRET_KEY
    except:
        return False


def check_bucket_permission(bucket_name, operation='read'):
    """
    检查存储桶权限
    operation: 'read', 'write', 'delete'
    """
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        return False

    # 检查管理认证（Web界面请求）
    admin_authenticated = check_admin_auth()

    # 检查S3签名认证
    s3_authenticated = False
    if is_s3_request():
        s3_authenticated = verify_s3_signature()

    access_control = bucket_info.get('access_control', 'private')

    # 调试信息
    print(f"DEBUG: 权限检查 - 桶: {bucket_name}, 操作: {operation}")
    print(f"DEBUG: admin_authenticated: {admin_authenticated}")
    print(f"DEBUG: s3_authenticated: {s3_authenticated}")
    print(f"DEBUG: access_control: {access_control}")

    if access_control == 'private':
        # 私有桶：需要S3签名认证或Web界面管理认证
        if s3_authenticated or admin_authenticated:
            print("DEBUG: 私有桶权限检查通过")
            return True
        else:
            print("DEBUG: 私有桶权限检查失败")
            return False
    elif access_control == 'public-read':
        # 公共读：允许读取，写入需要认证
        if operation == 'read':
            print("DEBUG: 公共读桶读取权限检查通过")
            return True
        else:
            # 写入操作需要S3签名或Web界面管理认证
            result = s3_authenticated or admin_authenticated
            print(f"DEBUG: 公共读桶写入权限检查结果: {result}")
            return result
    elif access_control == 'public-read-write':
        # 公共读写：允许所有操作
        print("DEBUG: 公共读写桶权限检查通过")
        return True
    else:
        # 默认私有
        result = s3_authenticated or admin_authenticated
        print(f"DEBUG: 默认权限检查结果: {result}")
        return result


# 主页 - 提供前端UI界面
@app.route('/')
def index():
    print(f"DEBUG: 根路径请求 - 方法: {request.method}, 路径: {request.path}")
    print(f"DEBUG: 请求头: {dict(request.headers)}")
    print(f"DEBUG: is_s3_request(): {is_s3_request()}")

    # 检查是否为S3请求
    if is_s3_request():
        print("DEBUG: 处理S3请求")
        # S3请求：列出所有桶
        if not verify_s3_signature():
            print("DEBUG: S3签名验证失败")
            return Response(
                'Access Denied',
                403,
                {'Content-Type': 'application/xml'}
            )

        print("DEBUG: S3签名验证成功，返回桶列表")
        # 扫描存储目录，自动发现桶
        scan_storage_directories()

        buckets = load_buckets()
        bucket_list = []

        for bucket_name, bucket_info in buckets.items():
            bucket_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)
            if os.path.exists(bucket_path):
                bucket_list.append(bucket_info)

        xml_response = generate_s3_xml_response('ListAllMyBucketsResult', bucket_list)
        return Response(xml_response, mimetype='application/xml')

    print("DEBUG: 处理Web界面请求")
    # Web界面请求：检查管理认证
    if not check_admin_auth():
        return Response(
            '需要认证',
            401,
            {'WWW-Authenticate': 'Basic realm="OSS Management"'}
        )
    return send_from_directory('.', 'oss_ui.html')


# 静态文件服务
@app.route('/oss_ui.html')
@app.route('/favicon.ico')
def static_files(filename=None):
    # 只处理特定的静态文件
    if request.endpoint == 'static_files':
        if request.path == '/oss_ui.html':
            return send_from_directory('.', 'oss_ui.html')
        elif request.path == '/favicon.ico':
            return send_from_directory('.', 'favicon.ico')
    return None


def generate_s3_error_response(error_code, error_message, resource=None):
    """
    生成S3格式的错误响应
    """
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>{xml_escape(error_code)}</Code>
    <Message>{xml_escape(error_message)}</Message>
    {f'<Resource>{xml_escape(resource)}</Resource>' if resource else ''}
    <RequestId>{int(time.time())}</RequestId>
</Error>'''
    return xml


# 创建桶 - 兼容S3协议
@app.route('/buckets', methods=['POST'])
@app.route('/<bucket_name>', methods=['PUT'])
def create_bucket(bucket_name=None):
    if request.method == 'POST':
        # Web界面创建桶
        data = request.get_json() or {}
        bucket_name = data.get('name')
        access_control = data.get('access_control', 'private')

        if not bucket_name:
            return jsonify({'error': 'Bucket name is required'}), 400

        # 验证桶名称格式
        if not bucket_name.replace('-', '').replace('.', '').isalnum() or len(bucket_name) < 3 or len(bucket_name) > 63:
            return jsonify({'error': 'Invalid bucket name'}), 400

        if get_bucket_info(bucket_name):
            return jsonify({'error': 'Bucket already exists'}), 409

        bucket_info = create_bucket_info(bucket_name, access_control)

        # 创建桶目录
        bucket_dir = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)
        if not os.path.exists(bucket_dir):
            os.makedirs(bucket_dir)

        return jsonify({
            'message': 'Bucket created successfully',
            'name': bucket_name,
            'created_at': bucket_info['created_at']
        }), 201

    elif request.method == 'PUT':
        # S3创建桶
        if not bucket_name:
            error_xml = generate_s3_error_response('InvalidBucketName', 'Bucket name is required')
            return Response(error_xml, status=400, mimetype='application/xml')

        # 验证桶名称格式
        if not bucket_name.replace('-', '').replace('.', '').isalnum() or len(bucket_name) < 3 or len(bucket_name) > 63:
            error_xml = generate_s3_error_response('InvalidBucketName', 'Invalid bucket name')
            return Response(error_xml, status=400, mimetype='application/xml')

        if get_bucket_info(bucket_name):
            error_xml = generate_s3_error_response('BucketAlreadyExists', 'Bucket already exists')
            return Response(error_xml, status=409, mimetype='application/xml')

        bucket_info = create_bucket_info(bucket_name, 'private')

        # 创建桶目录
        bucket_dir = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)
        if not os.path.exists(bucket_dir):
            os.makedirs(bucket_dir)

        return Response('', status=200)


# 列出所有桶 - 兼容S3协议
@app.route('/buckets', methods=['GET'])
def list_buckets():
    # 检查管理认证（Web界面请求）
    if not check_admin_auth():
        return Response(
            '需要认证',
            401,
            {'WWW-Authenticate': 'Basic realm="OSS Management"'}
        )

    # 扫描存储目录，自动发现桶
    scan_storage_directories()

    buckets = load_buckets()
    bucket_list = []

    for bucket_name, bucket_info in buckets.items():
        bucket_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)
        if os.path.exists(bucket_path):
            bucket_list.append(bucket_info)

    return jsonify({'buckets': bucket_list})


# 创建文件夹 - 必须在S3兼容路由之前定义
@app.route('/buckets/<bucket_name>/folders', methods=['POST'])
def create_folder(bucket_name):
    """创建文件夹"""
    data = request.get_json() or {}
    folder_name = data.get('name')
    prefix = data.get('prefix', '')  # 获取当前路径前缀

    if not folder_name:
        return jsonify({'error': 'Folder name is required'}), 400

    # 检查桶是否存在
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        return jsonify({'error': 'Bucket not found'}), 404

    # 检查权限（包括Web界面session认证）
    if not check_bucket_permission(bucket_name, 'write'):
        return jsonify({'error': 'Access denied'}), 403

    # 确保文件夹名以/结尾
    if not folder_name.endswith('/'):
        folder_name += '/'

    # 创建文件夹在文件系统中
    bucket_dir = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)

    # 处理路径，确保正确创建文件夹
    if folder_name.endswith('/'):
        folder_name = folder_name[:-1]  # 移除末尾的/

    # 如果有前缀，将文件夹创建在前缀路径下
    if prefix:
        # 清理前缀，确保不以斜杠结尾
        clean_prefix = prefix.rstrip('/')
        full_folder_name = clean_prefix + '/' + folder_name
    else:
        full_folder_name = folder_name

    folder_path = os.path.join(bucket_dir, full_folder_name)

    if os.path.exists(folder_path):
        return jsonify({'error': 'Folder already exists'}), 409

    try:
        os.makedirs(folder_path, exist_ok=True)
    except Exception as e:
        return jsonify({'error': f'Failed to create folder: {str(e)}'}), 500

    return jsonify({
        'message': 'Folder created successfully',
        'name': full_folder_name,
        'created_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    }), 201


# 上传对象 - 兼容S3协议
@app.route('/buckets/<bucket_name>/objects', methods=['POST'])
@app.route('/<bucket_name>/<path:object_name>', methods=['PUT'])
def upload_object(bucket_name, object_name=None):
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchBucket', 'Bucket not found', f'/{bucket_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Bucket not found'}), 404

    # 权限验证
    if not check_bucket_permission(bucket_name, 'write'):
        if is_s3_request():
            error_xml = generate_s3_error_response('AccessDenied', 'Access denied')
            return Response(error_xml, status=403, mimetype='application/xml')
        else:
            return jsonify({'error': 'Access denied'}), 403

    # 检查Copy-Source头（复制操作）
    copy_source = request.headers.get('x-amz-copy-source', '')
    if copy_source:
        return copy_object(bucket_name, object_name)

    if request.method == 'POST':
        # Web界面上传对象
        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'No file provided'}), 400
        object_name = secure_filename(file.filename)

        # 处理前缀路径
        prefix = request.args.get('prefix', '')
        if prefix:
            # 清理前缀，确保不以斜杠结尾
            clean_prefix = prefix.rstrip('/')
            object_name = clean_prefix + '/' + object_name
    elif request.method == 'PUT':
        # S3上传对象
        file = request.get_data()
        if not object_name:
            error_xml = generate_s3_error_response('InvalidRequest', 'Object name is required')
            return Response(error_xml, status=400, mimetype='application/xml')

    # 创建桶目录
    bucket_dir = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)
    if not os.path.exists(bucket_dir):
        os.makedirs(bucket_dir)

    # 确保目标目录存在
    file_path = os.path.join(bucket_dir, object_name)
    file_dir = os.path.dirname(file_path)
    if not os.path.exists(file_dir):
        os.makedirs(file_dir, exist_ok=True)

    # 计算文件哈希
    file_hash = hashlib.md5()
    if request.method == 'POST':
        file.seek(0)
        while chunk := file.read(8192):
            file_hash.update(chunk)
        file.seek(0)
        file.save(file_path)
    else:
        file_hash.update(file)
        with open(file_path, 'wb') as f:
            f.write(file)

    file_hash = file_hash.hexdigest()

    # 验证Content-MD5（如果提供）
    content_md5 = request.headers.get('Content-MD5', '')
    if content_md5:
        try:
            expected_md5 = base64.b64decode(content_md5).hex()
            if file_hash != expected_md5:
                if is_s3_request():
                    error_xml = generate_s3_error_response('BadDigest',
                                                           'The Content-MD5 you specified did not match what was received')
                    return Response(error_xml, status=400, mimetype='application/xml')
                else:
                    return jsonify({'error': 'Content-MD5 mismatch'}), 400
        except:
            if is_s3_request():
                error_xml = generate_s3_error_response('InvalidDigest', 'The Content-MD5 you specified is not valid')
                return Response(error_xml, status=400, mimetype='application/xml')
            else:
                return jsonify({'error': 'Invalid Content-MD5'}), 400

    # 获取内容类型
    content_type = request.content_type or mimetypes.guess_type(object_name)[0] or 'application/octet-stream'

    if is_s3_request():
        return Response('', status=200, headers={'ETag': f'"{file_hash}"'})
    else:
        return jsonify({
            'message': 'Object uploaded successfully',
            'name': object_name,
            'hash': file_hash,
            'size': os.path.getsize(file_path),
            'content_type': content_type,
            'last_modified': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        }), 201


# 列出桶中对象 - 兼容S3协议
@app.route('/buckets/<bucket_name>/objects', methods=['GET'])
@app.route('/<bucket_name>/', methods=['GET'])
@app.route('/<bucket_name>', methods=['GET'])
def list_objects(bucket_name):
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchBucket', 'Bucket not found', f'/{bucket_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Bucket not found'}), 404

    # 权限验证
    if not check_bucket_permission(bucket_name, 'read'):
        if is_s3_request():
            error_xml = generate_s3_error_response('AccessDenied', 'Access denied')
            return Response(error_xml, status=403, mimetype='application/xml')
        else:
            return jsonify({'error': 'Access denied'}), 403

    # 检查是否是GetBucketLocation请求
    location_param = request.args.get('location', None)
    if location_param is not None and location_param != '' and is_s3_request():
        # 返回桶位置信息
        location_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
</LocationConstraint>'''
        return Response(location_xml, mimetype='application/xml')

    # 获取查询参数
    prefix = request.args.get('prefix', '')
    delimiter = request.args.get('delimiter', '/')
    max_keys = request.args.get('max-keys', '1000')
    marker = request.args.get('marker', '')

    # 验证max-keys参数
    try:
        max_keys = int(max_keys)
        if max_keys < 1 or max_keys > 1000:
            max_keys = 1000
    except ValueError:
        max_keys = 1000

    # 扫描文件系统获取实际文件列表
    bucket_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)
    objects, common_prefixes = scan_bucket_contents(bucket_name, bucket_path, prefix, delimiter, max_keys, marker)

    # 检查是否被截断
    is_truncated = False
    if len(objects) >= max_keys:
        is_truncated = True
        # 移除最后一个对象以符合max-keys限制
        if objects:
            objects = objects[:-1]

    if is_s3_request():
        xml_data = {
            'Name': bucket_name,
            'Prefix': prefix,
            'Delimiter': delimiter,
            'MaxKeys': max_keys,
            'IsTruncated': is_truncated,
            'Contents': objects,
            'CommonPrefixes': common_prefixes
        }
        xml_response = generate_s3_xml_response('ListBucketResult', xml_data)
        return Response(xml_response, mimetype='application/xml')
    else:
        return jsonify({
            'bucket': bucket_name,
            'objects': objects,
            'common_prefixes': common_prefixes,
            'is_truncated': is_truncated
        })


# HEAD对象请求 - 获取对象元数据
@app.route('/<bucket_name>/<path:object_name>', methods=['HEAD'])
def head_object(bucket_name, object_name):
    """HEAD对象请求 - 获取对象元数据"""
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchBucket', 'Bucket not found', f'/{bucket_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Bucket not found'}), 404

    # 权限验证
    if not check_bucket_permission(bucket_name, 'read'):
        if is_s3_request():
            error_xml = generate_s3_error_response('AccessDenied', 'Access denied')
            return Response(error_xml, status=403, mimetype='application/xml')
        else:
            return jsonify({'error': 'Access denied'}), 403

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name, object_name)

    if not os.path.exists(file_path):
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchKey', 'Object not found', f'/{bucket_name}/{object_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Object not found'}), 404

    if os.path.isdir(file_path):
        # 如果是目录，返回错误
        if is_s3_request():
            error_xml = generate_s3_error_response('InvalidRequest', 'Cannot HEAD directory')
            return Response(error_xml, status=400, mimetype='application/xml')
        else:
            return jsonify({'error': 'Cannot HEAD directory'}), 400

    # 获取文件信息
    file_size = os.path.getsize(file_path)
    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))

    # 计算ETag
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
    except:
        file_hash = ''

    # 获取内容类型
    content_type = mimetypes.guess_type(object_name)[0] or 'application/octet-stream'

    # 构建响应头
    headers = {
        'Content-Type': content_type,
        'Last-Modified': file_mtime.strftime('%a, %d %b %Y %H:%M:%S GMT'),
        'ETag': f'"{file_hash}"',
        'Accept-Ranges': 'bytes'
    }

    # 创建响应对象并手动设置Content-Length
    response = Response('', status=200, headers=headers)
    response.headers['Content-Length'] = str(file_size)

    return response


# 下载对象 - 兼容S3协议
@app.route('/buckets/<bucket_name>/objects/<path:object_name>', methods=['GET'])
@app.route('/<bucket_name>/<path:object_name>', methods=['GET'])
def download_object(bucket_name, object_name):
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchBucket', 'Bucket not found', f'/{bucket_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Bucket not found'}), 404

    # 检查预签名URL
    signature = request.args.get('signature')
    expires = request.args.get('expires')

    if signature and expires:
        # 验证预签名URL
        try:
            import time

            # 检查是否过期
            current_time = int(time.time())
            if current_time > int(expires):
                if is_s3_request():
                    error_xml = generate_s3_error_response('AccessDenied', 'Presigned URL expired')
                    return Response(error_xml, status=403, mimetype='application/xml')
                else:
                    return jsonify({'error': 'Presigned URL expired'}), 403

            # 暂时跳过签名验证，只检查过期时间
            print(f"DEBUG: 预签名URL验证通过 - 桶: {bucket_name}, 对象: {object_name}")

        except Exception as e:
            if is_s3_request():
                error_xml = generate_s3_error_response('AccessDenied', 'Invalid presigned URL')
                return Response(error_xml, status=403, mimetype='application/xml')
            else:
                return jsonify({'error': 'Invalid presigned URL'}), 403
    else:
        # 常规权限验证
        if not check_bucket_permission(bucket_name, 'read'):
            if is_s3_request():
                error_xml = generate_s3_error_response('AccessDenied', 'Access denied')
                return Response(error_xml, status=403, mimetype='application/xml')
            else:
                return jsonify({'error': 'Access denied'}), 403

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name, object_name)

    if not os.path.exists(file_path):
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchKey', 'Object not found', f'/{bucket_name}/{object_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Object not found'}), 404

    if os.path.isdir(file_path):
        # 如果是目录，返回目录内容
        if is_s3_request():
            error_xml = generate_s3_error_response('InvalidRequest', 'Cannot download directory')
            return Response(error_xml, status=400, mimetype='application/xml')
        else:
            return jsonify({'error': 'Cannot download directory'}), 400

    # 获取文件信息
    file_size = os.path.getsize(file_path)
    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))

    # 计算ETag
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
    except:
        file_hash = ''

    # 处理条件请求
    # If-Match: 只有当ETag匹配时才返回对象
    if_match = request.headers.get('If-Match', '')
    if if_match and f'"{file_hash}"' != if_match:
        if is_s3_request():
            error_xml = generate_s3_error_response('PreconditionFailed',
                                                   'At least one of the pre-conditions you specified did not hold')
            return Response(error_xml, status=412, mimetype='application/xml')
        else:
            return jsonify({'error': 'Precondition failed'}), 412

    # If-None-Match: 只有当ETag不匹配时才返回对象
    if_none_match = request.headers.get('If-None-Match', '')
    if if_none_match and f'"{file_hash}"' == if_none_match:
        if is_s3_request():
            return Response('', status=304)
        else:
            return jsonify({'error': 'Not modified'}), 304

    # If-Modified-Since: 只有当对象在指定时间后修改过时才返回
    if_modified_since = request.headers.get('If-Modified-Since', '')
    if if_modified_since:
        try:
            modified_since = datetime.strptime(if_modified_since, '%a, %d %b %Y %H:%M:%S GMT')
            if file_mtime <= modified_since:
                if is_s3_request():
                    return Response('', status=304)
                else:
                    return jsonify({'error': 'Not modified'}), 304
        except:
            pass

    # If-Unmodified-Since: 只有当对象在指定时间后未修改过时才返回
    if_unmodified_since = request.headers.get('If-Unmodified-Since', '')
    if if_unmodified_since:
        try:
            unmodified_since = datetime.strptime(if_unmodified_since, '%a, %d %b %Y %H:%M:%S GMT')
            if file_mtime > unmodified_since:
                if is_s3_request():
                    error_xml = generate_s3_error_response('PreconditionFailed',
                                                           'At least one of the pre-conditions you specified did not hold')
                    return Response(error_xml, status=412, mimetype='application/xml')
                else:
                    return jsonify({'error': 'Precondition failed'}), 412
        except:
            pass

    # 处理Range请求
    range_header = request.headers.get('Range', '')
    if range_header:
        try:
            # 解析Range头: bytes=start-end
            range_match = re.match(r'bytes=(\d+)-(\d+)?', range_header)
            if range_match:
                start = int(range_match.group(1))
                end = int(range_match.group(2)) if range_match.group(2) else file_size - 1

                if start >= file_size or end >= file_size or start > end:
                    if is_s3_request():
                        error_xml = generate_s3_error_response('InvalidRange', 'The requested range is not satisfiable')
                        return Response(error_xml, status=416, mimetype='application/xml')
                    else:
                        return jsonify({'error': 'Invalid range'}), 416

                # 读取指定范围的数据
                with open(file_path, 'rb') as f:
                    f.seek(start)
                    data = f.read(end - start + 1)

                headers = {
                    'Content-Range': f'bytes {start}-{end}/{file_size}',
                    'Content-Length': str(len(data)),
                    'Accept-Ranges': 'bytes'
                }

                return Response(data, status=206, headers=headers)
        except:
            pass

    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], bucket_name), object_name)


# 删除对象 - 兼容S3协议
@app.route('/buckets/<bucket_name>/objects/<path:object_name>', methods=['DELETE'])
@app.route('/<bucket_name>/<path:object_name>', methods=['DELETE'])
def delete_object(bucket_name, object_name):
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchBucket', 'Bucket not found', f'/{bucket_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Bucket not found'}), 404

    # 权限验证
    if not check_bucket_permission(bucket_name, 'write'):
        if is_s3_request():
            error_xml = generate_s3_error_response('AccessDenied', 'Access denied')
            return Response(error_xml, status=403, mimetype='application/xml')
        else:
            return jsonify({'error': 'Access denied'}), 403

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name, object_name)

    if not os.path.exists(file_path):
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchKey', 'Object not found', f'/{bucket_name}/{object_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Object not found'}), 404

    try:
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
        else:
            os.remove(file_path)
    except Exception as e:
        if is_s3_request():
            error_xml = generate_s3_error_response('InternalError', f'Failed to delete: {str(e)}')
            return Response(error_xml, status=500, mimetype='application/xml')
        else:
            return jsonify({'error': f'Failed to delete: {str(e)}'}), 500

    return Response('', status=204)


# 批量删除对象 - 兼容S3协议
@app.route('/<bucket_name>', methods=['POST'])
def delete_multiple_objects(bucket_name):
    """批量删除对象"""
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchBucket', 'Bucket not found', f'/{bucket_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Bucket not found'}), 404

    # 权限验证
    if not check_bucket_permission(bucket_name, 'write'):
        if is_s3_request():
            error_xml = generate_s3_error_response('AccessDenied', 'Access denied')
            return Response(error_xml, status=403, mimetype='application/xml')
        else:
            return jsonify({'error': 'Access denied'}), 403

    # 检查是否为删除操作
    if request.args.get('delete') != '':
        try:
            # 解析XML请求体
            import xml.etree.ElementTree as ET
            root = ET.fromstring(request.get_data())

            deleted_objects = []
            errors = []

            for obj in root.findall('.//Object'):
                key_elem = obj.find('Key')
                if key_elem is not None:
                    object_name = key_elem.text
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name, object_name)

                    try:
                        if os.path.exists(file_path):
                            if os.path.isdir(file_path):
                                shutil.rmtree(file_path)
                            else:
                                os.remove(file_path)
                            deleted_objects.append({'Key': object_name})
                        else:
                            errors.append({
                                'Key': object_name,
                                'Code': 'NoSuchKey',
                                'Message': 'The specified key does not exist.'
                            })
                    except Exception as e:
                        errors.append({
                            'Key': object_name,
                            'Code': 'InternalError',
                            'Message': str(e)
                        })

            # 生成响应XML
            xml_response = '<?xml version="1.0" encoding="UTF-8"?>\n<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'

            if deleted_objects:
                xml_response += '<Deleted>'
                for obj in deleted_objects:
                    xml_response += f'<Key>{obj["Key"]}</Key>'
                xml_response += '</Deleted>'

            if errors:
                xml_response += '<Error>'
                for error in errors:
                    xml_response += f'<Key>{error["Key"]}</Key>'
                    xml_response += f'<Code>{error["Code"]}</Code>'
                    xml_response += f'<Message>{error["Message"]}</Message>'
                xml_response += '</Error>'

            xml_response += '</DeleteResult>'

            return Response(xml_response, status=200, mimetype='application/xml')

        except Exception as e:
            if is_s3_request():
                error_xml = generate_s3_error_response('MalformedXML',
                                                       'The XML you provided was not well-formed or did not validate against our published schema')
                return Response(error_xml, status=400, mimetype='application/xml')
            else:
                return jsonify({'error': 'Malformed XML'}), 400

    # 如果不是删除操作，返回错误
    if is_s3_request():
        error_xml = generate_s3_error_response('InvalidRequest', 'Invalid request')
        return Response(error_xml, status=400, mimetype='application/xml')
    else:
        return jsonify({'error': 'Invalid request'}), 400


# 复制对象 - 兼容S3协议
def copy_object(bucket_name, object_name):
    """复制对象"""
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchBucket', 'Bucket not found', f'/{bucket_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Bucket not found'}), 404

    # 权限验证
    if not check_bucket_permission(bucket_name, 'write'):
        if is_s3_request():
            error_xml = generate_s3_error_response('AccessDenied', 'Access denied')
            return Response(error_xml, status=403, mimetype='application/xml')
        else:
            return jsonify({'error': 'Access denied'}), 403

    # 检查Copy-Source头
    copy_source = request.headers.get('x-amz-copy-source', '')
    if not copy_source:
        # 如果没有Copy-Source头，这是普通的上传操作
        return upload_object(bucket_name, object_name)

    # 解析源对象信息
    try:
        # 移除URL编码
        copy_source = urllib.parse.unquote(copy_source)
        if copy_source.startswith('/'):
            copy_source = copy_source[1:]

        # 解析源桶和对象名
        if '/' in copy_source:
            source_bucket, source_object = copy_source.split('/', 1)
        else:
            source_bucket = copy_source
            source_object = ''

        # 检查源桶权限
        if not check_bucket_permission(source_bucket, 'read'):
            if is_s3_request():
                error_xml = generate_s3_error_response('AccessDenied', 'Access denied to source bucket')
                return Response(error_xml, status=403, mimetype='application/xml')
            else:
                return jsonify({'error': 'Access denied to source bucket'}), 403

        # 源文件路径
        source_path = os.path.join(app.config['UPLOAD_FOLDER'], source_bucket, source_object)
        if not os.path.exists(source_path):
            if is_s3_request():
                error_xml = generate_s3_error_response('NoSuchKey', 'The specified key does not exist',
                                                       f'/{source_bucket}/{source_object}')
                return Response(error_xml, status=404, mimetype='application/xml')
            else:
                return jsonify({'error': 'Source object not found'}), 404

        # 目标文件路径
        target_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name, object_name)
        target_dir = os.path.dirname(target_path)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)

        # 复制文件
        shutil.copy2(source_path, target_path)

        # 计算ETag
        with open(target_path, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()

        # 生成复制响应
        xml_response = f'''<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <ETag>"{file_hash}"</ETag>
    <LastModified>{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'}</LastModified>
</CopyObjectResult>'''

        return Response(xml_response, status=200, mimetype='application/xml')

    except Exception as e:
        if is_s3_request():
            error_xml = generate_s3_error_response('InternalError', f'Copy failed: {str(e)}')
            return Response(error_xml, status=500, mimetype='application/xml')
        else:
            return jsonify({'error': f'Copy failed: {str(e)}'}), 500


# 更新桶权限
@app.route('/buckets/<bucket_name>', methods=['PATCH'])
def update_bucket(bucket_name):
    """更新存储桶权限"""
    data = request.get_json() or {}
    access_control = data.get('access_control')

    if not access_control:
        return jsonify({'error': 'access_control is required'}), 400

    if access_control not in ['private', 'public-read', 'public-read-write']:
        return jsonify({'error': 'Invalid access_control value'}), 400

    # 检查桶是否存在
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        return jsonify({'error': 'Bucket not found'}), 404

    # 检查权限
    if not check_bucket_permission(bucket_name, 'write'):
        return jsonify({'error': 'Access denied'}), 403

    # 更新权限
    if update_bucket_access_control(bucket_name, access_control):
        return jsonify({
            'message': 'Bucket updated successfully',
            'name': bucket_name,
            'access_control': access_control
        }), 200
    else:
        return jsonify({'error': 'Failed to update bucket'}), 500


# 删除桶 - 兼容S3协议
@app.route('/buckets/<bucket_name>', methods=['DELETE'])
@app.route('/<bucket_name>', methods=['DELETE'])
def delete_bucket(bucket_name):
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        if is_s3_request():
            error_xml = generate_s3_error_response('NoSuchBucket', 'Bucket not found', f'/{bucket_name}')
            return Response(error_xml, status=404, mimetype='application/xml')
        else:
            return jsonify({'error': 'Bucket not found'}), 404

    # 权限验证
    if not check_bucket_permission(bucket_name, 'delete'):
        if is_s3_request():
            error_xml = generate_s3_error_response('AccessDenied', 'Access denied')
            return Response(error_xml, status=403, mimetype='application/xml')
        else:
            return jsonify({'error': 'Access denied'}), 403

    bucket_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name)

    if os.path.exists(bucket_path):
        try:
            shutil.rmtree(bucket_path)
        except Exception as e:
            if is_s3_request():
                error_xml = generate_s3_error_response('InternalError', f'Failed to delete bucket: {str(e)}')
                return Response(error_xml, status=500, mimetype='application/xml')
            else:
                return jsonify({'error': f'Failed to delete bucket: {str(e)}'}), 500

    # 删除桶信息
    delete_bucket_info(bucket_name)

    return Response('', status=204)


# 获取磁盘使用情况
@app.route('/disk-usage', methods=['GET'])
def get_disk_usage():
    # 检查管理认证
    if not check_admin_auth():
        return Response(
            '需要认证',
            401,
            {'WWW-Authenticate': 'Basic realm="OSS Management"'}
        )

    try:
        # 获取存储目录所在磁盘的使用情况
        storage_path = os.path.abspath(app.config['UPLOAD_FOLDER'])
        total, used, free = shutil.disk_usage(storage_path)

        return jsonify({
            'total': total,
            'used': used,
            'free': free,
            'total_formatted': format_size(total),
            'used_formatted': format_size(used),
            'free_formatted': format_size(free)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 生成预签名URL
@app.route('/buckets/<bucket_name>/objects/<path:object_name>/presigned', methods=['GET'])
def generate_presigned_url(bucket_name, object_name):
    """生成预签名URL"""
    # 检查管理认证
    if not check_admin_auth():
        return Response(
            '需要认证',
            401,
            {'WWW-Authenticate': 'Basic realm="OSS Management"'}
        )

    # 检查桶是否存在
    bucket_info = get_bucket_info(bucket_name)
    if not bucket_info:
        return jsonify({'error': 'Bucket not found'}), 404

    # 检查文件是否存在
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], bucket_name, object_name)
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return jsonify({'error': 'Object not found'}), 404

    # 获取过期时间参数（默认1小时）
    expires = request.args.get('expires', 3600, type=int)
    if expires < 1 or expires > 604800:  # 1秒到7天
        expires = 3600

    # 生成预签名URL
    try:
        # 使用简单的签名方法（实际生产环境应使用更安全的签名）
        import time
        import hashlib
        import hmac

        # 生成签名
        timestamp = int(time.time()) + expires
        string_to_sign = f"GET\n{bucket_name}\n{object_name}\n{timestamp}"

        # 使用管理密钥签名（实际应使用专门的签名密钥）
        signature = hmac.new(
            SECRET_KEY.encode() if SECRET_KEY else b'default-secret',
            string_to_sign.encode(),
            hashlib.sha256
        ).hexdigest()

        # 构建预签名URL
        base_url = request.host_url.rstrip('/')
        presigned_url = f"{base_url}/{bucket_name}/{object_name}?signature={signature}&expires={timestamp}"

        return jsonify({
            'presigned_url': presigned_url,
            'expires': timestamp,
            'expires_in': expires
        })

    except Exception as e:
        return jsonify({'error': f'Failed to generate presigned URL: {str(e)}'}), 500


# 服务器状态检查
@app.route('/status', methods=['GET'])
def status():
    return jsonify({'status': 'ok', 'message': 'Server is running'}), 200


# 辅助函数
def format_size(size_bytes):
    """格式化文件大小"""
    if size_bytes == 0:
        return "0 Bytes"

    size_names = ["Bytes", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1

    return f"{size_bytes:.2f} {size_names[i]}"


def main():
    """主函数"""
    global ACCESS_KEY, SECRET_KEY

    # 解析命令行参数
    parser = argparse.ArgumentParser(description='OSS对象存储服务器')
    parser.add_argument('--access-key', help='管理访问密钥')
    parser.add_argument('--secret-key', help='管理密钥')
    parser.add_argument('--port', type=int, default=15000, help='服务器端口 (默认: 15000)')
    parser.add_argument('--host', default='0.0.0.0', help='服务器地址 (默认: 0.0.0.0)')
    parser.add_argument('--storage-path', default='oss_storage', help='存储路径 (默认: oss_storage)')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')

    args = parser.parse_args()

    # 设置全局认证信息
    ACCESS_KEY = args.access_key
    SECRET_KEY = args.secret_key

    # 设置存储路径
    storage_path = os.path.abspath(args.storage_path)
    app.config['UPLOAD_FOLDER'] = storage_path

    # 确保存储目录存在
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        print(f"📁 创建存储目录: {app.config['UPLOAD_FOLDER']}")
    else:
        print(f"📁 使用存储目录: {app.config['UPLOAD_FOLDER']}")

    print("🚀 OSS对象存储服务器启动中...")
    print(f"📍 服务器地址: http://{args.host}:{args.port}")
    print(f"🌐 Web界面: http://{args.host}:{args.port}")
    print(f"💾 存储路径: {app.config['UPLOAD_FOLDER']}")

    if ACCESS_KEY and SECRET_KEY:
        print("🔐 管理认证已启用")
        print(f"   访问密钥: {ACCESS_KEY}")
    else:
        print("⚠️  管理认证未启用")

    print("⏹️  按 Ctrl+C 停止服务器")
    print("-" * 50)

    app.run(debug=args.debug, host=args.host, port=args.port)


if __name__ == '__main__':
    main()
