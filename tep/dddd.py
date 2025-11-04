# 安装依赖（在新电脑上执行这些命令）
# pip install flask
# pip install ddddocr
# pip install waitress
# https://nssm.cc/download
# nssm install dddocr_service "C:\Users\liujin\AppData\Local\Programs\Python\Python38\python.exe" "D:\dddd\dddd.py"

import base64
import logging
import os
from flask import Flask, request, jsonify
import ddddocr
from waitress import serve

# -----------------------
# 日志配置
# -----------------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "dddocr_service.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# -----------------------
# OCR 初始化
# -----------------------
try:
    ddocr = ddddocr.DdddOcr()
    logging.info("ddddocr 初始化完成")
except Exception as e:
    logging.error(f"OCR 初始化失败: {e}")
    raise

# -----------------------
# Flask App
# -----------------------
app = Flask(__name__)

@app.route('/dddocr', methods=['POST'])
def dddocr_route():
    try:
        data = request.json
        if not data or 'base64' not in data:
            return jsonify({"error": "缺少 base64 字段"}), 400

        image_data = base64.b64decode(data['base64'])
        result = ddocr.classification(image_data)
        logging.info(f"OCR 成功: {result}")
        return result
    except Exception as e:
        logging.exception("OCR 处理失败")
        return ""

# -----------------------
# 启动服务（固定大端口 15000）
# -----------------------
if __name__ == '__main__':
    port = 15000  # 固定端口，避免冲突
    logging.info(f"服务启动，端口 {port}")
    serve(app, host="10.10.32.32", port=port)
