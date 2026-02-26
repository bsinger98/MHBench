from concurrent.futures import ThreadPoolExecutor, as_completed
from openstack.connection import Connection
from src.utility.logging import get_logger
from typing import Any, cast

logger = get_logger()

NUM_PERMANENT_SUBNETS = 1
NUM_PERMANENT_NETS = 2
NUM_PERMANENT_SECURITY_GROUPS = 1

IMAGE_NAME_SUFFIX = "_image"


def get_image_name(host_name: str):
    return host_name + IMAGE_NAME_SUFFIX


class OpenstackImager:
    def __init__(
        self,
        openstack_conn: Connection,
    ):
        self.openstack_conn: Connection = openstack_conn

    def save_all_snapshots(self):
        logger.debug("Saving all snapshots...")
        instances = list(self.openstack_conn.list_servers())
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._save_snapshot, inst): inst for inst in instances}
            for future in as_completed(futures):
                future.result()

    def clean_snapshots(self):
        logger.debug("Cleaning all snapshots...")
        images = [img for img in self.openstack_conn.list_images() if "_image" in img.name]
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.openstack_conn.delete_image, img.id, True) for img in images]
            for future in as_completed(futures):
                future.result()

    def _save_snapshot(self, host):
        snapshot_name = get_image_name(host.name)
        # NOTE: `get_image()` expects an ID; use find_image(name) for name-based lookup.
        compute = cast(Any, self.openstack_conn.compute)
        existing = compute.find_image(snapshot_name)
        if existing:
            logger.debug(f"Image '{snapshot_name}' already exists. Deleting...")
            self.openstack_conn.delete_image(existing.id, wait=True)  # type: ignore

        logger.debug(f"Creating snapshot {snapshot_name} for instance {host.id}...")
        image = self.openstack_conn.create_image_snapshot(
            snapshot_name, host.id, wait=True
        )
        return image.id
