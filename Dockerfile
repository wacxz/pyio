FROM python:3.13-slim

WORKDIR /app

# 安装后端依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制后端代码
COPY *.py .
COPY *.html .

# 暴露端口
EXPOSE 15000

ENV ACCESS_KEY=pyioadmin
ENV SECRET_KEY=pyioadmin
ENV STORAGE_PATH=/data
ENV PORT=15000

# 启动命令
CMD python oss_server.py --access-key "$ACCESS_KEY" --secret-key "$SECRET_KEY" --host 0.0.0.0 --port "$PORT" --storage-path "$STORAGE_PATH"
