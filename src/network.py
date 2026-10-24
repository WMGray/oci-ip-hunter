"""OCI 虚拟网络管理模块：支持虚拟云网络与公网 IP 的完整读写操作。

涵盖 VCN、子网、路由表、安全列表，以及保留/临时公网 IPv4 的申请、绑定、解绑与释放。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci


class NetworkManager:
    """管理 OCI 虚拟网络拓扑及公网/预留 IPv4 的生命周期（申请、绑定、解绑、释放）。"""

    def __init__(
        self,
        network_client: oci.core.VirtualNetworkClient,
        compute_client: Optional[oci.core.ComputeClient] = None,
        identity_client: Optional[oci.identity.IdentityClient] = None,
        tenancy_id: str = "",
        region: str = "",
    ) -> None:
        self.client = network_client
        self.compute_client = compute_client
        self.identity_client = identity_client
        self.tenancy_id = tenancy_id
        self.region = region

    def _cid(self, compartment_id: Optional[str] = None) -> str:
        return compartment_id or self.tenancy_id

    # ==================== 读操作 (Read) ====================

    def list_vcns(self, compartment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取 VCN 虚拟云网络列表。"""
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_vcns, self._cid(compartment_id)
        ).data
        return [
            {
                "id": v.id,
                "name": v.display_name,
                "cidr": v.cidr_blocks or [v.cidr_block],
                "state": v.lifecycle_state,
                "default_route_table_id": v.default_route_table_id,
                "default_security_list_id": v.default_security_list_id,
                "dns_label": v.dns_label,
            }
            for v in rows
        ]

    def get_vcn(self, vcn_id: str) -> Dict[str, Any]:
        """获取单个 VCN 详情。"""
        v = self.client.get_vcn(vcn_id).data
        return {
            "id": v.id,
            "name": v.display_name,
            "cidr": v.cidr_blocks or [v.cidr_block],
            "state": v.lifecycle_state,
            "dns_label": v.dns_label,
        }

    def list_subnets(
        self,
        compartment_id: Optional[str] = None,
        vcn_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """获取子网列表，明确区分公网与私有属性。"""
        kwargs = {"vcn_id": vcn_id} if vcn_id else {}
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_subnets, self._cid(compartment_id), **kwargs
        ).data
        return [
            {
                "id": s.id,
                "name": s.display_name,
                "cidr": s.cidr_block,
                "vcn_id": s.vcn_id,
                "is_public": not s.prohibit_public_ip_on_vnic,
                "state": s.lifecycle_state,
                "route_table_id": s.route_table_id,
            }
            for s in rows
        ]

    def list_route_tables(
        self,
        compartment_id: Optional[str] = None,
        vcn_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """获取路由表及其出站规则列表。"""
        kwargs = {"vcn_id": vcn_id} if vcn_id else {}
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_route_tables, self._cid(compartment_id), **kwargs
        ).data
        return [
            {
                "id": r.id,
                "name": r.display_name,
                "vcn_id": r.vcn_id,
                "rules": [
                    {
                        "dest": rule.destination,
                        "entity_id": rule.network_entity_id,
                    }
                    for rule in getattr(r, "route_rules", []) or []
                ],
            }
            for r in rows
        ]

    def list_security_lists(
        self,
        compartment_id: Optional[str] = None,
        vcn_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """获取安全列表出入站安全规则。"""
        kwargs = {"vcn_id": vcn_id} if vcn_id else {}
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_security_lists, self._cid(compartment_id), **kwargs
        ).data
        return [
            {
                "id": sl.id,
                "name": sl.display_name,
                "vcn_id": sl.vcn_id,
                "ingress_count": len(getattr(sl, "ingress_security_rules", []) or []),
                "egress_count": len(getattr(sl, "egress_security_rules", []) or []),
            }
            for sl in rows
        ]

    def list_gateways(
        self,
        compartment_id: Optional[str] = None,
        vcn_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """获取 Internet 网关与 NAT 网关详情。"""
        cid = self._cid(compartment_id)
        kwargs = {"vcn_id": vcn_id} if vcn_id else {}
        igs = oci.pagination.list_call_get_all_results(
            self.client.list_internet_gateways, cid, **kwargs
        ).data
        ngs = oci.pagination.list_call_get_all_results(
            self.client.list_nat_gateways, cid, **kwargs
        ).data
        return {
            "internet_gateways": [
                {
                    "id": g.id,
                    "name": g.display_name,
                    "is_enabled": g.is_enabled,
                    "vcn_id": g.vcn_id,
                }
                for g in igs
            ],
            "nat_gateways": [
                {
                    "id": g.id,
                    "name": g.display_name,
                    "ip": g.nat_ip,
                    "vcn_id": g.vcn_id,
                }
                for g in ngs
            ],
        }

    # ==================== 预留 IPv4 与公网 IP 查询 ====================

    def list_reserved_ips(
        self,
        compartment_id: Optional[str] = None,
        unassigned_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """获取区域性预留公网 IPv4，支持闲置过滤与自动反查绑定实例名称。"""
        cid = self._cid(compartment_id)
        rows = oci.pagination.list_call_get_all_results(
            self.client.list_public_ips,
            scope="REGION",
            compartment_id=cid,
            lifetime="RESERVED",
        ).data

        res = []
        for r in rows:
            is_idle = r.lifecycle_state == "AVAILABLE" and not r.assigned_entity_id
            if unassigned_only and not is_idle:
                continue

            item = {
                "id": r.id,
                "ip": r.ip_address,
                "name": r.display_name,
                "state": r.lifecycle_state,
                "is_idle": is_idle,
                "time_created": str(r.time_created),
                "instance_name": None,
                "private_ip": None,
            }
            if not is_idle and r.assigned_entity_id and self.compute_client:
                try:
                    p = self.client.get_private_ip(r.assigned_entity_id).data
                    item["private_ip"] = p.ip_address
                    atts = oci.pagination.list_call_get_all_results(
                        self.compute_client.list_vnic_attachments,
                        compartment_id=cid,
                        vnic_id=p.vnic_id,
                    ).data
                    if atts and atts[0].instance_id:
                        inst = self.compute_client.get_instance(
                            atts[0].instance_id
                        ).data
                        item["instance_name"] = inst.display_name
                except Exception:
                    pass
            res.append(item)
        return res

    def list_public_ips(
        self,
        compartment_id: Optional[str] = None,
        lifetime: Optional[str] = None,
        unassigned_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """查询全量公网 IP（预留 + 各可用区动态分配给实例的临时 IP）。"""
        cid = self._cid(compartment_id)
        all_raw = []

        if lifetime in (None, "RESERVED"):
            all_raw.extend(
                oci.pagination.list_call_get_all_results(
                    self.client.list_public_ips,
                    scope="REGION",
                    compartment_id=cid,
                    lifetime="RESERVED",
                ).data
            )

        if lifetime in (None, "EPHEMERAL"):
            all_raw.extend(
                oci.pagination.list_call_get_all_results(
                    self.client.list_public_ips,
                    scope="REGION",
                    compartment_id=cid,
                    lifetime="EPHEMERAL",
                ).data
            )
            if self.identity_client:
                try:
                    ads = oci.pagination.list_call_get_all_results(
                        self.identity_client.list_availability_domains, cid
                    ).data
                    for ad in ads:
                        all_raw.extend(
                            oci.pagination.list_call_get_all_results(
                                self.client.list_public_ips,
                                scope="AVAILABILITY_DOMAIN",
                                compartment_id=cid,
                                availability_domain=ad.name,
                                lifetime="EPHEMERAL",
                            ).data
                        )
                except Exception:
                    pass

        res = []
        for r in all_raw:
            is_idle = r.lifecycle_state == "AVAILABLE" and not r.assigned_entity_id
            if unassigned_only and not is_idle:
                continue
            item = {
                "id": r.id,
                "ip": r.ip_address,
                "name": r.display_name,
                "lifetime": r.lifetime,
                "state": r.lifecycle_state,
                "is_idle": is_idle,
                "entity_type": r.assigned_entity_type,
                "instance_name": None,
                "private_ip": None,
            }
            if (
                not is_idle
                and r.assigned_entity_id
                and r.assigned_entity_type == "PRIVATE_IP"
                and self.compute_client
            ):
                try:
                    p = self.client.get_private_ip(r.assigned_entity_id).data
                    item["private_ip"] = p.ip_address
                    atts = oci.pagination.list_call_get_all_results(
                        self.compute_client.list_vnic_attachments,
                        compartment_id=cid,
                        vnic_id=p.vnic_id,
                    ).data
                    if atts and atts[0].instance_id:
                        inst = self.compute_client.get_instance(
                            atts[0].instance_id
                        ).data
                        item["instance_name"] = inst.display_name
                except Exception:
                    pass
            res.append(item)
        return res

    def get_public_ip(self, public_ip_id: str) -> Dict[str, Any]:
        """获取单个公网 IP 的详细属性。"""
        r = self.client.get_public_ip(public_ip_id).data
        return {
            "id": r.id,
            "ip": r.ip_address,
            "name": r.display_name,
            "lifetime": r.lifetime,
            "state": r.lifecycle_state,
            "assigned_entity_id": r.assigned_entity_id,
            "assigned_entity_type": r.assigned_entity_type,
        }

    # ==================== 写操作 (Write & IP Management) ====================

    def create_reserved_ip(
        self,
        compartment_id: Optional[str] = None,
        display_name: Optional[str] = None,
        private_ip_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """申请分配一个新的预留公网 IPv4（可直接绑定到指定私有 IP，或保留闲置）。"""
        cid = self._cid(compartment_id)
        details = oci.core.models.CreatePublicIpDetails(
            compartment_id=cid,
            lifetime="RESERVED",
            display_name=display_name,
            private_ip_id=private_ip_id,
        )
        res = self.client.create_public_ip(details).data
        return {
            "id": res.id,
            "ip": res.ip_address,
            "name": res.display_name,
            "state": res.lifecycle_state,
            "lifetime": res.lifetime,
        }

    def assign_public_ip(self, public_ip_id: str, private_ip_id: str) -> Dict[str, Any]:
        """将已有的闲置预留公网 IP 绑定到指定计算实例/网卡的私有 IP 上。"""
        details = oci.core.models.UpdatePublicIpDetails(private_ip_id=private_ip_id)
        res = self.client.update_public_ip(public_ip_id, details).data
        return {
            "id": res.id,
            "ip": res.ip_address,
            "assigned_private_ip_id": res.assigned_entity_id,
            "state": res.lifecycle_state,
        }

    def unassign_public_ip(self, public_ip_id: str) -> Dict[str, Any]:
        """解除预留公网 IP 的绑定，使其恢复为闲置 AVAILABLE 状态（不删除该 IP）。"""
        details = oci.core.models.UpdatePublicIpDetails(private_ip_id="")
        res = self.client.update_public_ip(public_ip_id, details).data
        return {"id": res.id, "ip": res.ip_address, "state": res.lifecycle_state}

    def delete_public_ip(self, public_ip_id: str) -> Dict[str, Any]:
        """彻底释放/删除预留公网 IP。"""
        self.client.delete_public_ip(public_ip_id)
        return {"id": public_ip_id, "status": "DELETED"}

    def assign_private_ip(
        self,
        vnic_id: str,
        ip_address: Optional[str] = None,
        display_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """在指定的 VNIC 网卡上分配额外的辅助私有 IPv4。"""
        details = oci.core.models.CreatePrivateIpDetails(
            vnic_id=vnic_id, ip_address=ip_address, display_name=display_name
        )
        res = self.client.create_private_ip(details).data
        return {
            "id": res.id,
            "ip": res.ip_address,
            "vnic_id": res.vnic_id,
            "subnet_id": res.subnet_id,
        }

    def delete_private_ip(self, private_ip_id: str) -> Dict[str, Any]:
        """删除 VNIC 上的辅助私有 IP。"""
        self.client.delete_private_ip(private_ip_id)
        return {"id": private_ip_id, "status": "DELETED"}
