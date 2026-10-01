



<!-- 添加到环境变量 -->
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc



<!-- 给mihomo二进制文件加权限 -->
sudo setcap cap_net_admin,cap_net_bind_service=+ep /usr/bin/mihomo