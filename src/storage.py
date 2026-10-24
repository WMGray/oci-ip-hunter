"""OCI 存储资源管理模块：支持块存储与对象存储的完整读写操作。

涵盖块存储卷 (Block Volumes)、引导卷、挂载/卸载，以及对象存储 Bucket/Object 的读写操作。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import oci


class StorageManager:
    """管理 OCI 存储资源。

    支持块存储卷、引导卷、卷挂载/卸载、快照备份以及对象存储 Bucket/Object 读写。
    """

    def __init__(
        self,
        blockstorage_client: oci.core.BlockstorageClient,
        object_storage_client: oci.object_storage.ObjectStorageClient,
        compute_client: Optional[oci.core.ComputeClient] = None,
        tenancy_id: str = "",
        region: str = "",
    ) -> None:
        self.block_client = blockstorage_client
        self.object_client = object_storage_client
        self.compute_client = compute_client
        self.tenancy_id = tenancy_id
        self.region = region
        self._namespace: Optional[str] = None

    def _cid(self, compartment_id: Optional[str] = None) -> str:
        return compartment_id or self.tenancy_id

    # ==================== 1. 块存储与引导卷 (Block Volumes) ====================

    def list_volumes(
        self,
        compartment_id: Optional[str] = None,
        availability_domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """列出块存储卷 (Block Volumes)。"""
        cid = self._cid(compartment_id)
        kwargs: Dict[str, Any] = {"compartment_id": cid}
        if availability_domain:
            kwargs["availability_domain"] = availability_domain
        rows = oci.pagination.list_call_get_all_results(
            self.block_client.list_volumes, **kwargs
        ).data
        return [
            {
                "id": v.id,
                "name": v.display_name,
                "size_gb": v.size_in_gbs,
                "vpus_per_gb": getattr(v, "vpus_per_gb", None),
                "ad": v.availability_domain,
                "state": v.lifecycle_state,
                "time_created": str(v.time_created),
            }
            for v in rows
        ]

    def list_boot_volumes(
        self,
        availability_domain: str,
        compartment_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """列出指定可用区的引导卷 (Boot Volumes)。"""
        cid = self._cid(compartment_id)
        rows = oci.pagination.list_call_get_all_results(
            self.block_client.list_boot_volumes,
            availability_domain=availability_domain,
            compartment_id=cid,
        ).data
        return [
            {
                "id": bv.id,
                "name": bv.display_name,
                "size_gb": bv.size_in_gbs,
                "vpus_per_gb": getattr(bv, "vpus_per_gb", None),
                "ad": bv.availability_domain,
                "state": bv.lifecycle_state,
                "image_id": bv.image_id,
                "time_created": str(bv.time_created),
            }
            for bv in rows
        ]

    def get_volume(self, volume_id: str) -> Dict[str, Any]:
        """获取单个存储卷详情。"""
        v = self.block_client.get_volume(volume_id).data
        return {
            "id": v.id,
            "name": v.display_name,
            "size_gb": v.size_in_gbs,
            "vpus_per_gb": getattr(v, "vpus_per_gb", None),
            "ad": v.availability_domain,
            "state": v.lifecycle_state,
            "time_created": str(v.time_created),
        }

    def list_volume_attachments(
        self,
        compartment_id: Optional[str] = None,
        instance_id: Optional[str] = None,
        volume_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """查询存储卷挂载状态。"""
        if not self.compute_client:
            raise RuntimeError("查询卷挂载关系需要 ComputeClient 支持")
        cid = self._cid(compartment_id)
        kwargs: Dict[str, Any] = {}
        if instance_id:
            kwargs["instance_id"] = instance_id
        if volume_id:
            kwargs["volume_id"] = volume_id

        rows = oci.pagination.list_call_get_all_results(
            self.compute_client.list_volume_attachments, cid, **kwargs
        ).data
        return [
            {
                "attachment_id": att.id,
                "instance_id": att.instance_id,
                "volume_id": att.volume_id,
                "name": att.display_name,
                "type": att.attachment_type,
                "state": att.lifecycle_state,
                "is_read_only": att.is_read_only,
            }
            for att in rows
        ]

    def create_volume(
        self,
        availability_domain: str,
        size_in_gbs: int = 50,
        display_name: Optional[str] = None,
        compartment_id: Optional[str] = None,
        vpus_per_gb: int = 10,
    ) -> Dict[str, Any]:
        """创建新的块存储卷 (Block Volume)。vpus_per_gb 10=均衡性能，20=高性能。"""
        cid = self._cid(compartment_id)
        details = oci.core.models.CreateVolumeDetails(
            compartment_id=cid,
            availability_domain=availability_domain,
            size_in_gbs=size_in_gbs,
            display_name=display_name,
            vpus_per_gb=vpus_per_gb,
        )
        v = self.block_client.create_volume(details).data
        return {
            "id": v.id,
            "name": v.display_name,
            "size_gb": v.size_in_gbs,
            "ad": v.availability_domain,
            "state": v.lifecycle_state,
        }

    def attach_volume(
        self,
        instance_id: str,
        volume_id: str,
        display_name: Optional[str] = None,
        is_read_only: bool = False,
        attachment_type: str = "paravirtualized",
    ) -> Dict[str, Any]:
        """将块存储卷挂载到计算实例（默认准虚拟化 paravirtualized，亦支持 iscsi）。"""
        if not self.compute_client:
            raise RuntimeError("挂载卷需要 ComputeClient 支持")

        if attachment_type.lower() == "iscsi":
            details = oci.core.models.AttachIScsiVolumeDetails(
                instance_id=instance_id,
                volume_id=volume_id,
                display_name=display_name,
                is_read_only=is_read_only,
            )
        else:
            details = oci.core.models.AttachParavirtualizedVolumeDetails(
                instance_id=instance_id,
                volume_id=volume_id,
                display_name=display_name,
                is_read_only=is_read_only,
            )

        att = self.compute_client.attach_volume(details).data
        return {
            "attachment_id": att.id,
            "instance_id": att.instance_id,
            "volume_id": att.volume_id,
            "state": att.lifecycle_state,
            "type": att.attachment_type,
        }

    def detach_volume(self, volume_attachment_id: str) -> Dict[str, Any]:
        """从计算实例卸载存储卷。"""
        if not self.compute_client:
            raise RuntimeError("卸载卷需要 ComputeClient 支持")
        self.compute_client.detach_volume(volume_attachment_id)
        return {"attachment_id": volume_attachment_id, "status": "DETACHING"}

    def update_volume(
        self,
        volume_id: str,
        size_in_gbs: Optional[int] = None,
        vpus_per_gb: Optional[int] = None,
        display_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """扩容存储卷或调整性能等级 (VPUs/GB)。"""
        details = oci.core.models.UpdateVolumeDetails(
            size_in_gbs=size_in_gbs,
            vpus_per_gb=vpus_per_gb,
            display_name=display_name,
        )
        v = self.block_client.update_volume(volume_id, details).data
        return {
            "id": v.id,
            "name": v.display_name,
            "size_gb": v.size_in_gbs,
            "vpus_per_gb": getattr(v, "vpus_per_gb", None),
            "state": v.lifecycle_state,
        }

    def delete_volume(self, volume_id: str) -> Dict[str, Any]:
        """彻底删除块存储卷。"""
        self.block_client.delete_volume(volume_id)
        return {"id": volume_id, "status": "TERMINATING"}

    # ==================== 2. 对象存储 (Object Storage) ====================

    def get_namespace(self) -> str:
        """获取租户在当前区域的对象存储命名空间 (Namespace)。"""
        if not self._namespace:
            self._namespace = self.object_client.get_namespace().data
        return self._namespace

    def list_buckets(
        self, compartment_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """获取对象存储存储桶 (Buckets) 列表。"""
        ns = self.get_namespace()
        cid = self._cid(compartment_id)
        rows = oci.pagination.list_call_get_all_results(
            self.object_client.list_buckets, ns, cid
        ).data
        return [
            {
                "name": b.name,
                "namespace": b.namespace,
                "time_created": str(b.time_created),
            }
            for b in rows
        ]

    def get_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """获取存储桶详情与统计。"""
        ns = self.get_namespace()
        b = self.object_client.get_bucket(ns, bucket_name).data
        return {
            "name": b.name,
            "namespace": b.namespace,
            "compartment_id": b.compartment_id,
            "public_access_type": b.public_access_type,
            "storage_tier": b.storage_tier,
            "approximate_count": getattr(b, "approximate_count", None),
            "approximate_size": getattr(b, "approximate_size", None),
            "time_created": str(b.time_created),
        }

    def create_bucket(
        self,
        bucket_name: str,
        compartment_id: Optional[str] = None,
        public_access_type: str = "NoPublicAccess",
    ) -> Dict[str, Any]:
        """创建对象存储桶。public_access_type: NoPublicAccess 或 ObjectRead。"""
        ns = self.get_namespace()
        cid = self._cid(compartment_id)
        details = oci.object_storage.models.CreateBucketDetails(
            name=bucket_name,
            compartment_id=cid,
            public_access_type=public_access_type,
        )
        b = self.object_client.create_bucket(ns, details).data
        return {
            "name": b.name,
            "namespace": b.namespace,
            "public_access": b.public_access_type,
        }

    def delete_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """删除空的存储桶。"""
        ns = self.get_namespace()
        self.object_client.delete_bucket(ns, bucket_name)
        return {"bucket_name": bucket_name, "status": "DELETED"}

    def list_objects(
        self,
        bucket_name: str,
        prefix: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """列出存储桶内的文件对象清单。"""
        ns = self.get_namespace()
        res = self.object_client.list_objects(
            ns, bucket_name, prefix=prefix, limit=limit
        ).data
        return [
            {
                "name": obj.name,
                "size_bytes": obj.size,
                "md5": obj.md5,
                "time_modified": str(obj.time_modified),
            }
            for obj in res.objects
        ]

    def put_object(
        self,
        bucket_name: str,
        object_name: str,
        data_or_file: Union[bytes, str, Path],
        content_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """上传对象到存储桶，支持传入 bytes 数据或本地文件路径。"""
        ns = self.get_namespace()
        if isinstance(data_or_file, (str, Path)) and Path(data_or_file).is_file():
            content = Path(data_or_file).read_bytes()
        elif isinstance(data_or_file, str):
            content = data_or_file.encode("utf-8")
        else:
            content = data_or_file

        resp = self.object_client.put_object(
            ns,
            bucket_name,
            object_name,
            content,
            content_type=content_type,
        )
        return {
            "bucket": bucket_name,
            "object": object_name,
            "opc_content_md5": resp.headers.get("opc-content-md5"),
            "status": "UPLOADED",
        }

    def get_object(
        self,
        bucket_name: str,
        object_name: str,
        dest_file_path: Optional[Union[str, Path]] = None,
    ) -> bytes:
        """下载对象数据。若提供 dest_file_path 则直接保存到本地文件并返回字节。"""
        ns = self.get_namespace()
        resp = self.object_client.get_object(ns, bucket_name, object_name)
        content = resp.data.content
        if dest_file_path:
            p = Path(dest_file_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
        return content

    def delete_object(self, bucket_name: str, object_name: str) -> Dict[str, Any]:
        """删除存储桶中的指定对象。"""
        ns = self.get_namespace()
        self.object_client.delete_object(ns, bucket_name, object_name)
        return {
            "bucket": bucket_name,
            "object": object_name,
            "status": "DELETED",
        }
