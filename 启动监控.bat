@echo off
title 员工IP流量监控服务
echo ========================================
echo   员工IP流量监控与限制中心
echo   CloudValley LuCI 集成
echo ========================================
echo.
echo 启动服务中...
echo 访问地址: http://127.0.0.1:5100
echo 按 Ctrl+C 停止服务
echo.

C:\Users\Administrator\.workbuddy\binaries\python\envs\netmon\Scripts\python.exe "%~dp0server.py"
pause
