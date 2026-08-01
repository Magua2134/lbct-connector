FROM node:18-slim

WORKDIR /app

# 安装依赖
COPY package.json ./
RUN npm install --production 2>&1 | tail -5

# 复制代码
COPY bot.js ./

# 创建数据目录
RUN mkdir -p /app/data

# 环境变量
ENV BOT_PORT=3000
ENV BOT_API_KEY=wechaty-bot-secret-2026
ENV NODE_ENV=production

# 健康检查
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# 启动
CMD ["node", "bot.js"]
