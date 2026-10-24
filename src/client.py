"""OCI Python SDK 统一客户端：整合计算、网络与存储三大子领域的读写管理。"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

import oci

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
for d in (current_dir, parent_dir):
    if d not in sys.path:
        sys.path.insert(0, d)

from auth import AuthManager  # noqa: E402
from compute import ComputeManager  # noqa: E402
from network import NetworkManager  # noqa: E402
from storage import StorageManager  # noqa: E402


class OCIClient:
    """高层统一客户端：开箱即用。

    整合计算 (Compute)、网络 (Network) 与存储 (Storage) 的全套读写能力。
    """

    def __init__(
        self,
        profile: str = "DEFAULT",
        region: Optional[str] = None,
        auth: Optional[AuthManager] = None,
        **auth_kwargs: Any,
    ) -> None:
        self.auth = auth or AuthManager(profile=profile, region=region, **auth_kwargs)
        self.signer, self.config, self.tenancy_id = self.auth.get_auth()
        self.region = self.config["region"]

        # 官方底层 SDK Client 句柄
        self.identity_client = oci.identity.IdentityClient(
            self.config, signer=self.signer
        )
        self.compute_client = oci.core.ComputeClient(self.config, signer=self.signer)
        self.network_client = oci.core.VirtualNetworkClient(
            self.config, signer=self.signer
        )
        self.blockstorage_client = oci.core.BlockstorageClient(
            self.config, signer=self.signer
        )
        self.object_storage_client = oci.object_storage.ObjectStorageClient(
            self.config, signer=self.signer
        )

        # 三大核心领域管理器（管理读写与生命周期）
        self.compute = ComputeManager(
            compute_client=self.compute_client,
            network_client=self.network_client,
            tenancy_id=self.tenancy_id,
            region=self.region,
        )
        self.network = NetworkManager(
            network_client=self.network_client,
            compute_client=self.compute_client,
            identity_client=self.identity_client,
            tenancy_id=self.tenancy_id,
            region=self.region,
        )
        self.storage = StorageManager(
            blockstorage_client=self.blockstorage_client,
            object_storage_client=self.object_storage_client,
            compute_client=self.compute_client,
            tenancy_id=self.tenancy_id,
            region=self.region,
        )

    # ==================== 身份与租户 ====================

    def tenancy(self) -> Dict[str, Any]:
        """获取当前租户基础信息。"""
        t = self.identity_client.get_tenancy(self.tenancy_id).data
        return {"id": t.id, "name": t.name, "home_region": t.home_region_key}

    def regions(self) -> List[Dict[str, Any]]:
        """获取租户已订阅区域。"""
        rows = oci.pagination.list_call_get_all_results(
            self.identity_client.list_region_subscriptions, self.tenancy_id
        ).data
        return [
            {
                "region": r.region_name,
                "status": r.status,
                "is_home": r.is_home_region,
            }
            for r in rows
        ]

    def compartments(self) -> List[Dict[str, Any]]:
        """获取可访问的所有 Compartment。"""
        rows = oci.pagination.list_call_get_all_results(
            self.identity_client.list_compartments,
            self.tenancy_id,
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE",
        ).data
        return [{"id": r.id, "name": r.name, "state": r.lifecycle_state} for r in rows]

    # ==================== 快捷业务委托 ====================

    def instances(
        self,
        compartment_id: Optional[str] = None,
        state: Optional[str] = None,
        with_network: bool = True,
    ) -> List[Dict[str, Any]]:
        """查询实例列表快捷入口。"""
        return self.compute.list_instances(
            compartment_id=compartment_id, state=state, with_network=with_network
        )

    def vcns(self, compartment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """查询 VCN 快捷入口。"""
        return self.network.list_vcns(compartment_id)

    def subnets(
        self,
        compartment_id: Optional[str] = None,
        vcn_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """查询子网快捷入口。"""
        return self.network.list_subnets(compartment_id, vcn_id)

    def reserved_ips(
        self,
        compartment_id: Optional[str] = None,
        unassigned_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """查询预留 IPv4 快捷入口。"""
        return self.network.list_reserved_ips(
            compartment_id=compartment_id, unassigned_only=unassigned_only
        )

    def public_ips(
        self,
        compartment_id: Optional[str] = None,
        lifetime: Optional[str] = None,
        unassigned_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """查询公网 IPv4 快捷入口。"""
        return self.network.list_public_ips(
            compartment_id=compartment_id,
            lifetime=lifetime,
            unassigned_only=unassigned_only,
        )
