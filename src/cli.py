"""简洁的 OCI 命令行工具，纯 Python SDK 实现。"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Sequence

# 确保脚本直调和项目根目录运行均可正确定位模块
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
for d in (current_dir, parent_dir):
    if d not in sys.path:
        sys.path.insert(0, d)

from auth import AuthManager  # noqa: E402
from client import OCIClient  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="OCI Python SDK 命令行（纯 SDK 调用）")
    p.add_argument("--profile", default="DEFAULT", help="profile 名称，默认 DEFAULT")
    p.add_argument("--region", help="覆盖或指定区域")
    p.add_argument("--instance-principals", action="store_true", help="使用实例主体")

    cmd = p.add_subparsers(dest="command", required=True)

    # 1. 认证管理
    a = cmd.add_parser("auth", help="会话认证管理")
    a_sub = a.add_subparsers(dest="action", required=True)
    st = a_sub.add_parser("status", help="认证有效状态")
    st.add_argument("--online", action="store_true", help="在线 API 核验")
    lg = a_sub.add_parser("login", help="浏览器 SSO 登录")
    lg.add_argument("--tenant", help="租户名称")
    lg.add_argument("--timeout", type=int, default=180, help="等待秒数")
    a_sub.add_parser("refresh", help="手动刷新 Token")

    # 2. 身份
    cmd.add_parser("tenancy", help="查询当前租户与订阅区域")

    # 3. 计算模块 (Compute)
    comp = cmd.add_parser("compute", help="计算资源操作（查询/启停/规格）")
    comp_sub = comp.add_subparsers(dest="comp_action", required=True)
    comp_list = comp_sub.add_parser("list", help="列出实例")
    comp_list.add_argument("--state", help="状态过滤 (RUNNING 等)")
    comp_sub.add_parser("shapes", help="列出可用规格")
    comp_sub.add_parser("images", help="列出可用镜像")

    c_start = comp_sub.add_parser("start", help="启动实例")
    c_start.add_argument("--instance-id", required=True)
    c_stop = comp_sub.add_parser("stop", help="停止实例")
    c_stop.add_argument("--instance-id", required=True)
    c_stop.add_argument("--force", action="store_true")
    c_re = comp_sub.add_parser("restart", help="重启实例")
    c_re.add_argument("--instance-id", required=True)
    c_re.add_argument("--force", action="store_true")

    # 向下兼容 instances 快捷命令
    inst = cmd.add_parser("instances", help="查询计算实例列表（快捷方式）")
    inst.add_argument("--state", help="按状态过滤 (RUNNING, STOPPED 等)")
    inst.add_argument("--no-network", action="store_true", help="不包含网络挂载")

    # 4. 网络模块 (Network)
    net = cmd.add_parser("network", help="虚拟网络拓扑与 IP 管理")
    net_sub = net.add_subparsers(dest="resource", required=True)
    net_sub.add_parser("vcns", help="VCN 列表")
    net_sub.add_parser("subnets", help="子网列表")
    net_sub.add_parser("routes", help="路由表规则")
    net_sub.add_parser("security-lists", help="安全列表规则")
    net_sub.add_parser("gateways", help="Internet 与 NAT 网关")

    # 5. 公网与预留 IP (快捷方式)
    ip = cmd.add_parser("public-ip", help="查询预留与公网 IPv4")
    ip.add_argument(
        "--type",
        choices=["all", "reserved", "ephemeral"],
        default="all",
        help="IP 类型",
    )
    ip.add_argument(
        "--unassigned-only", action="store_true", help="仅显示闲置未绑定的预留 IP"
    )

    # 6. 存储模块 (Storage)
    stor = cmd.add_parser("storage", help="块存储卷与对象存储管理")
    stor_sub = stor.add_subparsers(dest="stor_resource", required=True)
    stor_sub.add_parser("volumes", help="列出块存储卷")
    s_bv = stor_sub.add_parser("boot-volumes", help="列出引导卷")
    s_bv.add_argument("--ad", required=True, help="可用区名称 (Availability Domain)")
    stor_sub.add_parser("buckets", help="列出对象存储桶")
    s_objs = stor_sub.add_parser("objects", help="列出存储桶内的文件对象")
    s_objs.add_argument("--bucket", required=True, help="存储桶名称")
    s_objs.add_argument("--prefix", help="文件名前缀过滤")

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    args = _parser().parse_args(argv)
    auth = AuthManager(
        profile=args.profile,
        region=args.region,
        use_instance_principals=args.instance_principals,
    )

    try:
        if args.command == "auth":
            if args.action == "login":
                res = auth.login(args.tenant, args.timeout)
            elif args.action == "refresh":
                res = auth.refresh()
            else:
                res = auth.status(online=getattr(args, "online", False))
            sys.stdout.write(json.dumps(res, ensure_ascii=False, indent=2) + "\n")
            return 0

        client = OCIClient(auth=auth)

        if args.command == "tenancy":
            res = {"tenancy": client.tenancy(), "regions": client.regions()}
        elif args.command == "instances":
            res = client.instances(state=args.state, with_network=not args.no_network)
        elif args.command == "compute":
            if args.comp_action == "list":
                res = client.compute.list_instances(state=args.state)
            elif args.comp_action == "shapes":
                res = client.compute.list_shapes()
            elif args.comp_action == "images":
                res = client.compute.list_images()
            elif args.comp_action == "start":
                res = client.compute.start(args.instance_id)
            elif args.comp_action == "stop":
                res = client.compute.stop(args.instance_id, force=args.force)
            elif args.comp_action == "restart":
                res = client.compute.restart(args.instance_id, force=args.force)
        elif args.command == "network":
            if args.resource == "vcns":
                res = client.network.list_vcns()
            elif args.resource == "subnets":
                res = client.network.list_subnets()
            elif args.resource == "routes":
                res = client.network.list_route_tables()
            elif args.resource == "security-lists":
                res = client.network.list_security_lists()
            elif args.resource == "gateways":
                res = client.network.list_gateways()
        elif args.command == "public-ip":
            if args.type == "reserved":
                res = client.network.list_reserved_ips(
                    unassigned_only=args.unassigned_only
                )
            else:
                lifetime = None if args.type == "all" else args.type.upper()
                res = client.network.list_public_ips(
                    lifetime=lifetime, unassigned_only=args.unassigned_only
                )
        elif args.command == "storage":
            if args.stor_resource == "volumes":
                res = client.storage.list_volumes()
            elif args.stor_resource == "boot-volumes":
                res = client.storage.list_boot_volumes(availability_domain=args.ad)
            elif args.stor_resource == "buckets":
                res = client.storage.list_buckets()
            elif args.stor_resource == "objects":
                res = client.storage.list_objects(
                    args.bucket, prefix=getattr(args, "prefix", None)
                )

        sys.stdout.write(json.dumps(res, ensure_ascii=False, indent=2) + "\n")
        return 0
    except Exception as e:
        sys.stderr.write(json.dumps({"error": str(e)}, ensure_ascii=False) + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
