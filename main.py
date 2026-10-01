import os
import staypresent

# 健康检查端点
staypresent.web.json({"status": "running"})

# 防止休眠：每 4 分钟访问一次自己
# ★ 部署成功后，把下面的 URL 换成你的 Koyeb 应用地址
staypresent.cron("https://your-app-name.koyeb.app", interval=240)

if __name__ == "__main__":
    staypresent.run(
        "bot.py",
        port=int(os.getenv("PORT", 8080)),
        restart_on_crash=True,
        max_restarts=5,
        restart_delay=2.0,
    )
