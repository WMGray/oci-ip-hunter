"""OCI 计算资源管理模块：支持计算实例的读写与生命周期操作。

涵盖实例查询、启停重启、规格升降级 (Flex OCPU/RAM) 及虚拟网卡挂载等。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci


class ComputeManager:
    """管理 OCI 计算实例、硬件规格、镜像与生命周期操作。"""

    def __init__(
        self,
        compute_client: oci.core.ComputeClient,
        network_client: oci.core.VirtualNetworkClient,
        tenancy_id: str,
        region: str,
    ) -> None:
        self.client = compute_client
        self.network_client = network_client
        self.tenancy_id = tenancy_id
        self.region = region

    def _cid(self, compartment_id: Optional[str] = None) -> str:
        return compartment_id or self.tenancy_id

    # ==================== 读操作 (Read) ====================

    def list_instances(
        self,
        compartment_id: Optional[str] = None,
        state: Optional[str] = None,
        with_network: bool = True,
    ) -> List[Dict[str, Any]]:
        """获取计算实例列表，支持按生命周期状态过滤并可自动附带网卡详情。"""
        cid = self._cid(compartment_id)
        kwargs = {"lifecycle_state": state} if state else {}
        raw = oci.pagination.list_call_get_all_results(
            self.client.list_instances, cid, **kwargs
        ).data

        results = []
        for inst in raw:
            item = self._format_instance(inst)
            if with_network:
                item["vnics"] = self.get_instance_vnics(inst.id, inst.compartment_id)
            results.append(item)
        return results

    def get_instance(
        self, instance_id: str, with_network: bool = True
    ) -> Dict[str, Any]:
        """获取单个计算实例的详细信息。"""
        inst = self.client.get_instance(instance_id).data
        item = self._format_instance(inst)
        if with_network:
            item["vnics"] = self.get_instance_vnics(inst.id, inst.compartment_id)
        return item

    def get_instance_vnics(
        self, instance_id: str, compartment_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """获取指定计算实例绑定的所有 VNIC（网卡）及公私网 IPv4。"""
        cid = self._cid(compartment_id)
        atts = oci.pagination.list_call_get_all_results(
            self.client.list_vnic_attachments,
            compartment_id=cid,
            instance_id=instance_id,
        ).data

        vnics = []
        for att in atts:
            if att.lifecycle_state != "ATTACHED":
                continue
            v = self.network_client.get_vnic(att.vnic_id).data
            vnics.append(
                {
                    "attachment_id": att.id,
                    "vnic_id": v.id,
                    "name": v.display_name,
                    "is_primary": v.is_primary,
                    "state": v.lifecycle_state,
                    "private_ip": v.private_ip,
                    "public_ip": v.public_ip,
                    "mac": v.mac_address,
                    "subnet_id": v.subnet_id,
                }
            )
        vnics.sort(key=lambda x: not x["is_primary"])
        return vnics

    def list_shapes(
        self,
        compartment_id: Optional[str] = None,
        availability_domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """查询可用的实例规格列表（Shape），如 VM.Standard.A1.Flex 等。"""
        cid = self._cid(compartment_id)
        kwargs = (
            {"availability_domain": availability_domain} if availability_domain else {}
        )
        shapes = oci.pagination.list_call_get_all_results(
            self.client.list_shapes, cid, **kwargs
        ).data
        return [
            {
                "shape": s.shape,
                "ocpus": s.ocpus,
                "memory_in_gbs": s.memory_in_gbs,
                "processor_description": s.processor_description,
                "is_flexible": getattr(s, "is_flexible", False),
            }
            for s in shapes
        ]

    def list_images(
        self,
        compartment_id: Optional[str] = None,
        operating_system: Optional[str] = None,
        shape: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """查询可用操作系统镜像（如 Ubuntu, Oracle Linux）。"""
        cid = self._cid(compartment_id)
        kwargs: Dict[str, Any] = {}
        if operating_system:
            kwargs["operating_system"] = operating_system
        if shape:
            kwargs["shape"] = shape

        images = oci.pagination.list_call_get_all_results(
            self.client.list_images, cid, **kwargs
        ).data
        return [
            {
                "id": img.id,
                "name": img.display_name,
                "os": img.operating_system,
                "os_version": img.operating_system_version,
                "state": img.lifecycle_state,
                "time_created": str(img.time_created),
            }
            for img in images
        ]

    # ==================== 写操作 (Write & Lifecycle) ====================

    def action(self, instance_id: str, action: str) -> Dict[str, Any]:
        """执行实例电源操作：START, STOP, RESET, SOFTRESET, SOFTSTOP。"""
        valid_actions = {"START", "STOP", "RESET", "SOFTRESET", "SOFTSTOP"}
        act = action.upper()
        if act not in valid_actions:
            raise ValueError(f"无效的实例操作: {action}，支持: {valid_actions}")
        res = self.client.instance_action(instance_id, act).data
        return {"id": res.id, "name": res.display_name, "state": res.lifecycle_state}

    def start(self, instance_id: str) -> Dict[str, Any]:
        """启动实例。"""
        return self.action(instance_id, "START")

    def stop(self, instance_id: str, force: bool = False) -> Dict[str, Any]:
        """停止实例（默认平滑关机 SOFTSTOP，force=True 为强制关机 STOP）。"""
        return self.action(instance_id, "STOP" if force else "SOFTSTOP")

    def restart(self, instance_id: str, force: bool = False) -> Dict[str, Any]:
        """重启实例（默认平滑重启 SOFTRESET，force=True 为硬重启 RESET）。"""
        return self.action(instance_id, "RESET" if force else "SOFTRESET")

    def update_shape(
        self,
        instance_id: str,
        shape: Optional[str] = None,
        ocpus: Optional[float] = None,
        memory_in_gbs: Optional[float] = None,
    ) -> Dict[str, Any]:
        """变更实例规格或配置（针对 Flex 弹性配置可调整 OCPU 和内存）。"""
        shape_config = None
        if ocpus is not None or memory_in_gbs is not None:
            shape_config = oci.core.models.UpdateInstanceShapeConfigDetails(
                ocpus=ocpus, memory_in_gbs=memory_in_gbs
            )
        details = oci.core.models.UpdateInstanceDetails(
            shape=shape, shape_config=shape_config
        )
        updated = self.client.update_instance(instance_id, details).data
        return self._format_instance(updated)

    def terminate(
        self, instance_id: str, preserve_boot_volume: bool = True
    ) -> Dict[str, Any]:
        """终止/销毁计算实例（默认保留引导卷）。"""
        self.client.terminate_instance(
            instance_id, preserve_boot_volume=preserve_boot_volume
        )
        return {
            "instance_id": instance_id,
            "status": "TERMINATING",
            "preserve_boot_volume": preserve_boot_volume,
        }

    def attach_vnic(
        self,
        instance_id: str,
        subnet_id: str,
        display_name: Optional[str] = None,
        private_ip: Optional[str] = None,
        assign_public_ip: bool = False,
    ) -> Dict[str, Any]:
        """为计算实例挂载额外的辅助网卡 (VNIC)。"""
        vnic_details = oci.core.models.CreateVnicDetails(
            subnet_id=subnet_id,
            display_name=display_name,
            private_ip=private_ip,
            assign_public_ip=assign_public_ip,
        )
        att_details = oci.core.models.AttachVnicDetails(
            instance_id=instance_id, create_vnic_details=vnic_details
        )
        att = self.client.attach_vnic(att_details).data
        return {
            "attachment_id": att.id,
            "vnic_id": att.vnic_id,
            "state": att.lifecycle_state,
        }

    def detach_vnic(self, vnic_attachment_id: str) -> Dict[str, Any]:
        """从计算实例卸载辅助网卡 (VNIC)。"""
        self.client.detach_vnic(vnic_attachment_id)
        return {"attachment_id": vnic_attachment_id, "status": "DETACHING"}

    # ==================== 格式化辅助 ====================

    def _format_instance(self, inst: Any) -> Dict[str, Any]:
        sc = getattr(inst, "shape_config", None)
        return {
            "id": inst.id,
            "name": inst.display_name,
            "state": inst.lifecycle_state,
            "shape": inst.shape,
            "ocpus": getattr(sc, "ocpus", None),
            "memory_gb": getattr(sc, "memory_in_gbs", None),
            "ad": inst.availability_domain,
            "fault_domain": inst.fault_domain,
            "compartment_id": inst.compartment_id,
            "time_created": str(inst.time_created),
        }
